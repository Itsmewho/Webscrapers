# Connections web?
import random
from datetime import datetime
from utils.helpers import reset, red
from utils.session import verify_session
from flask import Flask, jsonify, request
from bson.objectid import ObjectId
from db.db_operations import find_documents
from db.audit import log_audit_event
from connection.connect_redis import redis_client
from login.reset_pass import reset_password
from login.unlock_account import unlock_account
from utils.sendmail import (
    confirm_token,
    send_email,
    serializer,
)


app = Flask(__name__)


@app.route("/")
def home():
    return "Flask server is running!"


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

    user = find_documents("admin", {"email": email})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    user_id = str(user[0]["_id"])
    code = random.randint(100000, 999999)
    try:
        # Send the 2FA code via email
        send_email(
            to_email=email,
            subject="Your 2FA Code",
            body=f"Your 2FA code is {code} Please enter it to complete the login process.",
        )

        user_id = email  # Encrypt email to get the user ID equivalent
        log_audit_event(
            user_id=user_id,
            email=email,
            action="2FA Code Sent",
            details={"code": code},
        )

        return jsonify(
            {"success": True, "message": "2FA code sent successfully", "code": code}
        )
    except Exception as e:
        log_audit_event(
            user_id=user_id,
            email=email,
            action="2FA Code Sending Failed",
            details={"error": str(e)},
        )
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

    if str(code) == str(expected_code):
        return jsonify({"success": True, "message": "2FA code verified"})
    else:
        return jsonify({"success": False, "message": "Invalid 2FA code"}), 401


@app.route("/reset-password/<token>", methods=["POST"])
def reset_password_route(token):

    data = request.json
    new_password = data.get("new_password")
    if not new_password:
        return jsonify({"success": False, "message": "New password is required"}), 400

    email = confirm_token(token, salt="password-reset-salt")
    if not email:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 400

    response = reset_password(token, new_password)

    # Log only if the reset is successful
    if response["success"]:
        log_audit_event(
            user_id=email,
            email=email,
            action="PASSWORD_RESET",
            details={"ip_address": request.remote_addr, "timestamp": datetime.now()},
        )

    status_code = 200 if response["success"] else 400
    return jsonify(response), status_code


@app.route("/unlock-account/<token>", methods=["POST"])
def unlock_account_route(token):

    try:
        email = confirm_token(token, salt="unlock-account-salt")
        if not email:
            return (
                jsonify({"success": False, "message": "Invalid or expired token"}),
                400,
            )

        response = unlock_account(token)
        # Log success or failure
        if response["success"]:
            log_audit_event(
                user_id=email,
                email=response.get("email", "Unknown"),
                action="ACCOUNT_UNLOCKED",
                details={"method": "email_token", "ip_address": request.remote_addr},
            )
        else:
            log_audit_event(
                user_id=email,
                email=response.get("email", "Unknown"),
                action="ACCOUNT_UNLOCK_FAILED",
                details={
                    "reason": response.get("message"),
                    "method": "email_token",
                    "ip_address": request.remote_addr,
                },
            )

        status_code = 200 if response["success"] else 400
        return jsonify(response), status_code

    except Exception as e:
        log_audit_event(
            user_id="N/A",
            email="Unknown",
            action="SERVER_ERROR",
            details={"error": str(e), "method": "unlock_account_route"},
        )
        return jsonify({"success": False, "message": "Server error occurred"}), 500


@app.route("/protected", methods=["GET"])
def protected():

    session_token = request.headers.get("Authorization")
    if not session_token:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user_id = verify_session(session_token)
    if not user_id:
        return jsonify({"success": False, "message": "Session expired or invalid"}), 401

    # Retrieve user data from MongoDB (if needed)
    user = find_documents("admin", {"_id": ObjectId(user_id)})
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
                    "message": "Too many attempts. Try again later.",
                }
            ),
            429,
        )

    attempts = redis_client.incr(f"rate_limit:login:{email}")
    if attempts > 5:
        redis_client.expire(f"rate_limit:login:{email}", 300)
        return jsonify({"success": False, "message": "Too many attempts"}), 429

    return


if __name__ == "__main__":
    import logging

    logging.basicConfig(
        filename="flask_server.log",
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    # # for decorating postman --->
    # for rule in app.url_map.iter_rules():
    #     print(
    #         f"Endpoint: {rule.endpoint} | Methods: {', '.join(rule.methods)} | URL: {rule}"
    #     )
    app.run(debug=True, port=5000)
