# Connections web?
import random, bcrypt, jwt, uuid, redis
from utils.helpers import reset, red
from utils.session import verify_session
from flask import Flask, jsonify, request
from db.db_operations import find_documents, update_documents
from db.audit import log_audit_event
from connection.connect_redis import redis_client
from utils.sendmail import (
    generate_confirmation_token,
    confirm_token,
    send_email,
    serializer,
)

app = Flask(__name__)


@app.route("/confirm/2fa/<token>", methods=["GET"])
def confirm_2fa_email(token):
    try:
        email = confirm_token(token)
        if email:
            return jsonify(
                {"success": True, "message": "Email confirmed!", "email": email}
            )
        else:
            raise ValueError(red + "Invalid token" + reset)
    except Exception:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 400


@app.route("/generate-token", methods=["POST"])
def generate_token():
    data = request.json
    email = data.get("email")
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    if redis_client.get(f"rate_limit:{email}"):
        return (
            jsonify(
                {"success": False, "message": "Too many requests, try again later"}
            ),
            429,
        )

    token = serializer.dumps(email, salt="email-confirm-salt")
    return jsonify({"success": True, "token": token})


@app.route("/send-2fa", methods=["POST"])
def send_2fa():
    data = request.json
    email = data.get("email")
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    code = random.randint(100000, 999999)
    try:
        # Send the 2FA code via email
        send_email(
            to_email=email,
            subject="Your 2FA Code",
            body=f"Your 2FA code is {code}. Please enter it to complete the login process.",
        )
        return jsonify(
            {"success": True, "message": "2FA code sent successfully", "code": code}
        )
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/verify-2fa", methods=["POST"])
def verify_2fa():

    data = request.json
    code = data.get("code")
    expected_code = data.get("expected_code")

    if not code or not expected_code:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Both code and expected_code are required",
                }
            ),
            400,
        )

    email = data.get("email")
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    user = find_documents("admin", {"email": email})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    user = user[0]  # Get the first result

    # Check if the account is locked
    if user.get("account_locked", False):
        log_audit_event(
            user_id=str(user["_id"]),
            email=user["email"],
            action="ACCOUNT_LOCKED_ATTEMPT",
            details={"method": "email", "ip_address": request.remote_addr},
        )
        return jsonify({"success": False, "message": "Account is locked"}), 403

    # Verify the 2FA code
    if str(code) == str(expected_code):
        log_audit_event(
            user_id=str(user["_id"]),
            email=user["email"],
            action="2FA_VERIFIED",
            details={"method": "email", "ip_address": request.remote_addr},
        )
        return jsonify({"success": True, "message": "2FA code verified"})

    # Log failed attempts
    log_audit_event(
        user_id=str(user["_id"]),
        email=user["email"],
        action="2FA_FAILED",
        details={"method": "email", "ip_address": request.remote_addr},
    )
    return jsonify({"success": False, "message": "Invalid 2FA code"}), 401


@app.route("/lock-account", methods=["POST"])
def lock_account():

    data = request.json
    email = data.get("email")
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    user = find_documents("admin", {"email": email})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    update_documents("admin", {"email": email}, {"$set": {"account_locked": True}})
    log_audit_event(
        user_id=str(user[0]["_id"]),
        email=user[0]["email"],
        action="ACCOUNT_LOCKED",
        details={"method": "admin_request", "ip_address": request.remote_addr},
    )
    return jsonify({"success": True, "message": "Account locked successfully"})


@app.route("/unlock-account", methods=["POST"])
def unlock_account():

    data = request.json
    email = data.get("email")
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    user = find_documents("admin", {"email": email})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    update_documents("admin", {"email": email}, {"$set": {"account_locked": False}})
    log_audit_event(
        user_id=str(user[0]["_id"]),
        email=user[0]["email"],
        action="ACCOUNT_UNLOCKED",
        details={"method": "admin_request", "ip_address": request.remote_addr},
    )
    return jsonify({"success": True, "message": "Account unlocked successfully"})


@app.route("/send-reset-email", methods=["POST"])
def send_reset_email():
    data = request.json
    email = data.get("email")
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    user = find_documents("admin", {"email": email})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    token = generate_confirmation_token(email)
    reset_link = f"http://127.0.0.1:5000/reset-password/{token}"
    send_email(
        to_email=email,
        subject="Password Reset Request",
        body=f"""
        <p>Hello,</p>
        <p>Click the link below to reset your password:</p>
        <a href="{reset_link}">Reset Password</a>
        <p>This link will expire in 5 minutes.</p>
        """,
    )
    log_audit_event(
        user_id=str(user[0]["_id"]),
        email=user[0]["email"],
        action="PASSWORD_RESET_REQUEST",
        details={"ip_address": request.remote_addr},
    )
    return jsonify({"success": True, "message": "Password reset email sent"})


@app.route("/reset-password/<token>", methods=["POST"])
def reset_password(token):
    data = request.json
    new_password = data.get("new_password")
    if not new_password:
        return jsonify({"success": False, "message": "New password is required"}), 400

    email = confirm_token(token)
    if not email:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 400

    hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    update_documents("admin", {"email": email}, {"$set": {"password": hashed_password}})
    log_audit_event(
        user_id=email,
        email=email,
        action="PASSWORD_RESET",
        details={"ip_address": request.remote_addr},
    )
    return jsonify({"success": True, "message": "Password reset successfully"})


@app.route("/protected", methods=["GET"])
def protected():
    session_token = request.headers.get("Authorization")
    if not session_token:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user_id = verify_session(session_token)
    if not user_id:
        return jsonify({"success": False, "message": "Session expired or invalid"}), 401

    # Retrieve user data from MongoDB (if needed)
    user = find_documents["admin"].find_one({"_id": user_id})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    return jsonify({"success": True, "message": f"Welcome, {user['email']}!"})


@app.route("/rate-limited-login", methods=["GET"])
def rate_limited_login():
    data = request.json
    email = data.get("email")
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    if redis_client.get(f"rate_limit:login:{email}"):
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Too many login attempts. Try again later.",
                }
            ),
            429,
        )

    # Set rate limit (e.g., 1 attempt per 30 seconds)
    redis_client.set(f"rate_limit:login:{email}", "1", ex=30)

    return


if __name__ == "__main__":
    app.run(debug=True)
