import bcrypt, requests
from utils.session import create_jwt
from utils.auth import input_masking
from db.db_operations import find_documents
from db.audit import log_audit_event
from connection.connect_redis import redis_client
from scrapers.scraper_menu import scraper_menu
from utils.sendmail import send_email
from utils.auth import (
    get_system_info,
    sha256_encrypt,
    lock_account,
    normalize_system_info,
)
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


def login():
    typing_effect(green + "Welcome to Login" + reset)

    identifier = input_quit_handle(green + "Enter your email: ").lower()
    hashed_name = sha256_encrypt(identifier)
    admin = find_documents("admin", {"name": hashed_name})  # lol
    if not admin:
        typing_effect(red + "No account found with the provided credentials!" + reset)
        sleep()
        clear()
        return
    if redis_client.get(f"rate_limit:login:{hashed_name}"):
        typing_effect(red + "Too many login attempts! Please try again later." + reset)
        sleep()
        clear()
        return

    redis_client.set(f"rate_limit:login:{hashed_name}", "5", ex=30)

    password = input_masking(red + f"Enter your password:{reset} ")

    admin = admin[0]

    if not bcrypt.checkpw(password.encode(), admin["password"].encode()):
        typing_effect(red + "Incorrect password! Your account is locked." + reset)
        lock_account(admin)
        return

    if admin.get("account_locked", True):
        typing_effect(red + "Your account is locked. Contact support." + reset)
        send_email(
            admin["email"],
            "Admin Account Locked",
            "Someone is trying to login,..",
        )
        sleep()
        clear()
        return

    token = create_jwt(str(admin["_id"]), admin["email"])

    log_audit_event(
        user_id=str(admin["_id"]),
        email=admin["email"],
        action="Login",
        details={"token": token},
    )

    if not handle_2fa(admin, token):
        typing_effect(red + "Login process terminated due to 2FA failure." + reset)
        return

    system_info = get_system_info()
    system_log = find_documents("admin_log", {})
    system_log = [
        {key: value for key, value in log.items() if key != "_id"} for log in system_log
    ]  # Remove the _id field if present

    normalized_system_info = normalize_system_info(system_info)
    normalized_system_log = normalize_system_info(system_log)

    if normalized_system_info not in normalized_system_log:
        typing_effect(red + "System info mismatch! Your account is locked." + reset)
        lock_account(admin)
        return
    else:
        typing_effect(green + "System verified" + reset)
        sleep()
        clear()

    scraper_menu(admin)


def handle_2fa(admin, token):
    if admin.get("2fa_method") is True:
        typing_effect(blue + "Sending 2FA code to your email..." + reset)
        try:
            response = requests.post(
                "http://127.0.0.1:5000/send-2fa", json={"email": admin["email"]}
            )
            response.raise_for_status()
            expected_code = response.json().get("code")
            if not expected_code:
                typing_effect(red + "Failed to retrieve 2FA code from server." + reset)
                return False
        except requests.RequestException as e:
            typing_effect(
                red + f"Error sending 2FA code: {str(e)}. Login denied." + reset
            )
            return False

        # Retrieve expected 2FA code
        expected_code = response.json().get("code")
        if not expected_code:
            typing_effect(red + "Failed to retrieve 2FA code from server." + reset)
            return False

        # Prompt admin for 2FA code
        code = input_quit_handle("Enter the 2FA code sent to your email: ").strip()
        try:
            verification_response = requests.post(
                "http://127.0.0.1:5000/verify-2fa",
                json={"code": code, "expected_code": expected_code, "token": token},
            )
            verification_response.raise_for_status()
            if verification_response.json().get("success"):
                print(green + "2FA verification successful!" + reset)
                return True
            else:
                typing_effect(red + "Invalid 2FA code. Login denied." + reset)
                return False
        except requests.RequestException as e:
            typing_effect(
                red + f"2FA verification failed: {str(e)}. Login denied." + reset
            )
            return False
    else:
        typing_effect(blue + "2FA is not enabled for this account." + reset)
        sleep()
        clear()
        return True
