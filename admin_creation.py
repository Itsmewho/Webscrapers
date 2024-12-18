# Admin creation for login.

import json
from pathlib import Path
from utils.auth import sha256_encrypt, bcrypt_hash, get_system_info, store_log
from utils.helpers import green, red, blue, reset, typing_effect, input_quit_handle

# Paths for storing data:

DATA_DIR = Path("./data")
ADMIN_JSON = DATA_DIR / "admin.json"
ADMIN_LOG_JSON = DATA_DIR / "admin_log.json"

# Ensure data exists
DATA_DIR.mkdir(exist_ok=True)


def create_admin():
    typing_effect("Admin Creation!")
    name = input_quit_handle(green + f"Enter name:")
    email = input_quit_handle(green + f"Enter Email:")
    password = input_quit_handle(green + f"Enter password:")
    sec_password = input_quit_handle(green + f"Enter secondary password:")

    admin_data = {
        "name": name,
        "email": email,
        "password": password,
        "sec_password": sec_password,
    }

    print(green + "\n--- Admin Data ---")
    for key, value in admin_data.items():
        print(f"{key.capitalize()}: {value}")

    confirmation = (
        input_quit_handle(blue + "\nDo you confirm this data? (yes/no):")
        .strip()
        .lower()
    )
    if confirmation != "yes":
        typing_effect(red + "Admin creation cancelled." + reset)
        return

    encrypted_admin_data = {
        "name": sha256_encrypt(name),
        "email": sha256_encrypt(email),
        "password": bcrypt_hash(password),
        "sec_password": bcrypt_hash(sec_password),
    }

    system_info = get_system_info()

    with open(ADMIN_JSON, "w") as admin_file:
        json.dump(encrypted_admin_data, admin_file, indent=4)
        typing_effect(green + "Admin data saved successfully." + reset)

    with open(ADMIN_LOG_JSON, "w") as log_file:
        json.dump(system_info, log_file, indent=4)
        print(green + "System log saved successfully." + reset)


if __name__ == "__main__":
    try:
        # Prevent re-creation if admin.json exists
        if ADMIN_JSON.exists():
            print(
                red
                + "Admin data already exists. Admin creation is not allowed."
                + reset
            )
        else:
            print(blue + "Creating admin data..." + reset)
            create_admin()

            print(blue + "Gathering and encrypting system information..." + reset)
            system_info = get_system_info()

            log_file_path = Path("./data/admin_log.json")
            store_log(system_info, log_file_path)

            print(
                green
                + "Admin creation and system log storage completed successfully!"
                + reset
            )
    except Exception as e:
        print(red + f"An error occurred: {e}" + reset)
