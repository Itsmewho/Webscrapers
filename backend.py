# Connections web?
import redis
import uuid
import jwt
import random
from utils.helpers import reset, red
from utils.session import verify_session, verify_jwt
from flask import Flask, jsonify, request
from db.db_operations import find_documents
from db.audit import log_audit_event
from connection.connect_redis import redis_client
from utils.sendmail import (
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
    token = data.get("token")

    if not code or not expected_code or not token:
        return jsonify({"success": False, "message": "All fields are required"}), 400

    user_id, email = verify_jwt(token)
    if not user_id or not email:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 401

    user = find_documents("admin", {"email": email})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    user = user[0]  # Get the first result

    # Verify the 2FA code
    if str(code) == str(expected_code):
        log_audit_event(
            user_id=str(user["_id"]),
            email=user["email"],
            action="2FA_VERIFIED",
            details={"method": "email", "ip_address": request.remote_addr},
        )
        return jsonify({"success": True, "message": "2FA code verified"})

    log_audit_event(
        user_id=str(user["_id"]),
        email=user["email"],
        action="2FA_FAILED",
        details={"method": "email", "ip_address": request.remote_addr},
    )
    return jsonify({"success": False, "message": "Invalid 2FA code"}), 401


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
