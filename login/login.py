import bcrypt, requests
from utils.session import create_jwt
from utils.auth import input_masking
from utils.sendmail import send_email
from db.db_operations import find_documents
from scrapers.scraper_menu import scraper_menu
from utils.auth import get_system_info, sha256_encrypt
from utils.helpers import (
    input_quit_handle,
    normalize_system_info,
    log_login_time,
    typing_effect,
    start_backend,
    sleep,
    red,
    green,
    blue,
    reset,
    clear,
)

# Global var:
backend_process = None


def login():

    start_backend()
    typing_effect(green + "Welcome to Login" + reset)
    identifier = input_quit_handle("Enter your email: ").lower()
    password = input_masking("Enter your password: ")

    hashed_name = sha256_encrypt(identifier)

    # Check if the user is an admin
    admin = find_documents("admin", {"name": hashed_name})
    if admin:
        admin = admin[0]

        # Verify password
        if not bcrypt.checkpw(password.encode(), admin["password"].encode()):
            typing_effect(red + "Incorrect password! Your account is locked." + reset)
            send_email(
                admin["email"],
                "Admin Account Locked",
                "Your admin account has been locked due to failed login attempts.",
            )
            sleep()
            clear()
            return

        # Check if the account is locked
        if admin.get("account_locked", False):
            typing_effect(red + "Your account is locked. Contact support." + reset)
            sleep()
            clear()
            return

        # Create JWT for the session
        token = create_jwt(str(admin["_id"]), admin["email"])

        # 2FA Flow
        if admin.get("2fa_method") == "email":
            print(blue + "Sending 2FA code to your email..." + reset)
            try:
                # Initiate 2FA flow using Flask backend
                response = requests.post(
                    "http://127.0.0.1:5000/send-2fa", json={"email": admin["email"]}
                )
                response.raise_for_status()
            except requests.RequestException as e:
                typing_effect(
                    red
                    + f"Error sending 2FA code: {str(e)}. Login denied. Flask offline."
                    + reset
                )
                return

            # Retrieve the expected 2FA code
            expected_code = response.json().get("code")
            if not expected_code:
                typing_effect(red + "Failed to retrieve 2FA code from server." + reset)
                return

            # Prompt admin to enter the code
            code = input_quit_handle(
                green + "Enter the 2FA code sent to your email: "
            ).strip()

            # Verify the 2FA code with the JWT
            try:
                verification_response = requests.post(
                    "http://127.0.0.1:5000/verify-2fa",
                    json={"code": code, "expected_code": expected_code, "token": token},
                )
                verification_response.raise_for_status()
            except requests.RequestException as e:
                typing_effect(
                    red + f"2FA verification failed: {str(e)}. Login denied." + reset
                )
                return

            if verification_response.json().get("success"):
                print(green + "2FA verification successful!" + reset)
            else:
                typing_effect(red + "Invalid 2FA code. Login denied." + reset)
                return
        else:
            typing_effect(blue + "2FA is not enabled for this account." + reset)

        # Successful login: Proceed to Admin Dashboard
        print(green + "Login successful! Proceeding to Admin Dashboard..." + reset)
        sleep()
        clear()
        scraper_menu(admin)
        return

    typing_effect(red + "No account found with the provided credentials!" + reset)
    sleep()
    return


def admin_login_flow(admin, password):
    typing_effect(blue + "User Detected" + reset)

    # Admins have only 1 attempt
    if not bcrypt.checkpw(password.encode(), admin["password"].encode()):
        typing_effect(red + "Incorrect password! Your account is locked." + reset)
        send_email(
            admin["email"],
            "Admin Account Locked",
            "Your admin account has been locked due to failed login attempts.",
        )
        return

    if admin.get("2fa_method") == "email":
        typing_effect(blue + "Sending 2FA code to your email..." + reset)
        try:
            # Initiate 2FA flow using Flask backend
            response = requests.post(
                "http://127.0.0.1:5000/send-2fa", json={"email": admin["email"]}
            )
            response.raise_for_status()
        except requests.RequestException as e:
            typing_effect(
                red
                + f"Error sending 2FA code: {str(e)}. Login denied. Flask offline"
                + reset
            )
            return

        # Retrieve the expected 2FA code
        expected_code = response.json().get("code")
        if not expected_code:
            typing_effect(red + "Failed to retrieve 2FA code from server." + reset)
            return

        # Prompt admin to enter the code
        code = input_quit_handle("Enter the 2FA code sent to your email: ").strip()

        # Verify the 2FA code
        try:
            verification_response = requests.post(
                "http://127.0.0.1:5000/verify-2fa",
                json={"code": code, "expected_code": expected_code},
            )
            verification_response.raise_for_status()

            if verification_response.json().get("success"):
                print(green + "2FA verification successful!" + reset)
            else:
                typing_effect(red + "2FA verification failed. Login denied." + reset)
                return

        except requests.RequestException as e:
            typing_effect(
                red + f"2FA verification failed: {str(e)}. Login denied." + reset
            )
            return

    elif admin.get("2fa_method") == "none":
        typing_effect(blue + "2FA is disabled for this account." + reset)
    else:
        typing_effect(blue + "Skipping 2FA for system info match." + reset)

    # Fetch System Info
    system_info = get_system_info()

    # Fetch Last Login Log
    last_log = find_documents("admin_log", {"name": admin["name"]})

    # Check if last log exists
    if not last_log:
        log_login_time("admin_log", admin["name"], system_info)
        print(green + "Admin login successful! Proceeding to program." + reset)
        # Proceed to scraper_menu
        sleep()
        clear()
        scraper_menu(admin)
        return

    # Normalize system info for comparison

    normalized_system_info = normalize_system_info(system_info)
    normalized_last_log = normalize_system_info(last_log.get("system_info", {}))

    # Compare System Info
    if normalized_system_info != normalized_last_log:
        typing_effect(red + "System info mismatch! Your account is locked." + reset)

        send_email(
            admin["email"],
            "Admin Account Locked",
            "Your admin account has been locked due to suspicious login attempts.",
        )
        return

    # Proceed to program
    sleep()
    clear()
    scraper_menu(admin)
