import os, bcrypt
from utils.auth import input_masking
from db.audit import log_audit_event
from itsdangerous import URLSafeTimedSerializer
from connection.connect_redis import redis_client
from db.db_operations import find_documents, update_documents
from utils.sendmail import send_email
from utils.helpers import (
    input_quit_handle,
    typing_effect,
    sleep,
    red,
    green,
    blue,
    reset,
    clear,
)

serializerreset = URLSafeTimedSerializer(os.getenv("RESET_KEY"))


def generate_confirmation_token(email, salt="password-reset-salt"):
    return serializerreset.dumps(email, salt=salt)


def confirm_reset_token(token, salt="password-reset-salt", expiration=300):
    try:
        email = serializerreset.loads(token, salt=salt, max_age=expiration)
    except Exception:
        return None
    return email


def send_reset_email(email):

    user = find_documents("admin", {"email": email})
    if not user:
        return {"success": False, "message": "User not found"}

    token = generate_confirmation_token(email, salt="password-reset-salt")
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
    return {"success": True, "message": "Password reset email sent"}


def reset_password(token, new_password):

    email = confirm_reset_token(token, salt="password-reset-salt")
    if not email:
        return {"success": False, "message": "Invalid or expired token"}

    hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    try:
        update_documents(
            "admin", {"email": email}, {"$set": {"password": hashed_password}}
        )
        return {"success": True, "message": "Password reset successfully"}
    except Exception as e:
        return {"success": False, "message": f"Failed to reset password: {str(e)}"}


def reset_terminal():
    typing_effect(blue + "Reset your password" + reset)

    email = input_quit_handle(green + "Enter your email: ")
    # May add prompt for secoundair password here:

    rate_limit_key = f"rate_limit:reset:{email}"
    if redis_client.get(rate_limit_key):
        typing_effect(red + "Too many attempts. Please try again later." + reset)
        sleep()
        clear()
        return

    attempts = redis_client.incr(rate_limit_key)
    if attempts == 1:
        redis_client.expire(rate_limit_key, 300)

    if attempts > 5:
        typing_effect(
            red + "Too many attempts. Please try again after 5 minutes." + reset
        )
        sleep()
        clear()
        return

    result = send_reset_email(email)
    typing_effect(result["message"])

    if result["success"]:
        while True:
            token = input_quit_handle(
                "Enter the code from your email:", lowercase=False
            ).strip()

            email = confirm_reset_token(token, salt="password-reset-salt")
            if not email:
                typing_effect(
                    red + "Invalid or expired token. Please try again." + reset
                )
                continue

            admin = find_documents("admin", {"email": email})
            if not admin:
                typing_effect(red + "User not found. Please try again." + reset)
                return

            admin = admin[0]

            while True:
                resetpass = input_masking(red + "Enter your new password: " + reset)
                new_password = input_masking(
                    red + "Confirm your new password: " + reset
                )

                if resetpass != new_password:
                    typing_effect(
                        red + "Passwords do not match. Please try again." + reset
                    )
                    continue

                if len(new_password) < 6:
                    typing_effect(
                        red + "Password must be at least 6 characters long." + reset
                    )
                    continue

                reset_result = reset_password(token, new_password)
                typing_effect(reset_result["message"])

                # Log success or failure of password reset
                action = (
                    "Password reset success"
                    if reset_result["success"]
                    else "Password reset failed"
                )
                log_audit_event(
                    user_id=str(admin["_id"]),
                    email=admin["email"],
                    action=action,
                )

                if reset_result["success"]:
                    typing_effect(
                        green
                        + "Password reset successfully! You can now log in."
                        + reset
                    )
                    sleep()
                    clear()
                    return
                else:
                    typing_effect(
                        red + "Failed to reset password. Please try again." + reset
                    )
                    break
    else:
        typing_effect(
            red
            + "Failed to send reset email. Please check your email and try again."
            + reset
        )
        sleep()
