import os
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

serializerunlock = URLSafeTimedSerializer(os.getenv("UNLOCK_KEY"))


def generate_confirmation_token(email, salt="unlock-account-salt"):

    return serializerunlock.dumps(email, salt=salt)


def confirm_unlock_token(token, salt="unlock-account-salt", expiration=300):
    try:
        email = serializerunlock.loads(token, salt=salt, max_age=expiration)
    except Exception:
        return None
    return email


def send_unlock_account(email):

    user = find_documents("admin", {"email": email})
    if not user:
        return {"success": False, "message": "User not found"}

    token = generate_confirmation_token(email, salt="unlock-account-salt")
    unlock_link = f"http://127.0.0.1:5000/unlock-account/{token}"
    send_email(
        to_email=email,
        subject="Account Unlock Request",
        body=f"""
        <p>Hello,</p>
        <p>Click the link below to unlock your account:</p>
        <a href="{unlock_link}">Unlock Account</a>
        <p>This link will expire in 5 minutes.</p>
        """,
    )
    return {"success": True, "message": "Unlock email sent"}


def unlock_account(token):

    email = confirm_unlock_token(token, salt="unlock-account-salt")
    if not email:
        print("Failed to confirm token")
        return {"success": False, "message": "Invalid or expired token"}

    try:
        update_documents("admin", {"email": email}, {"$set": {"account_locked": False}})
        return {"success": True, "message": "Account unlocked successfully"}
    except Exception as e:
        return {"success": False, "message": f"Failed to Unlock the account: {str(e)}"}


def unlock_terminal():

    typing_effect(blue + "Unlock your Account" + reset)

    email = input_quit_handle("Enter the email to unlock: ")

    rate_limit_key = f"rate_limit:unlock:{email}"
    if redis_client.get(rate_limit_key):
        typing_effect(red + "Too many attempts. Please try again later." + reset)
        sleep()
        return

    # Increment attempts
    attempts = redis_client.incr(rate_limit_key)
    if attempts == 1:
        redis_client.expire(rate_limit_key, 300)

    if attempts > 5:
        typing_effect(
            red + "Too many attempts. Please try again after 5 minutes." + reset
        )
        sleep()
        return

    admin = find_documents("admin", {"email": email})
    if not admin:
        typing_effect(red + "User not found. Please try again." + reset)
        return

    admin = admin[0]

    result = send_unlock_account(email)
    typing_effect(result["message"])

    if result["success"]:
        admin = find_documents("admin", {"email": email})
        if not admin:
            typing_effect(red + "User not found. Please try again." + reset)
            return

        while True:
            token = input_quit_handle(
                "Enter the code you received in your email: ", lowercase=False
            ).strip()
            unlock_result = unlock_account(token)
            print(unlock_result["message"])

            if unlock_result["success"]:
                typing_effect(green + "Account unlocked! You can now log in." + reset)
                sleep()
                clear()
                return
            else:
                print(red + "Invalid token, please try again." + reset)
                sleep()

            admin = admin[0]
            action = (
                "Account unlock success"
                if unlock_result["success"]
                else "Account unlock failed"
            )
            log_audit_event(
                user_id=str(admin["_id"]), email=admin["email"], action=action
            )

    else:
        typing_effect(
            red
            + "Failed to send reset email. Please check your email and try again."
            + reset
        )
        sleep()
