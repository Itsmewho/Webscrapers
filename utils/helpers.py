# frequent use
import os, time, subprocess
from datetime import datetime
from colorama import Style, Fore
from db.db_operations import update_documents, find_documents


# Global vars:

reset = Style.RESET_ALL
blue = Fore.BLUE
yellow = Fore.YELLOW
red = Fore.RED
green = Fore.GREEN

backend_process = None


def sleep(delay=0.35):
    time.sleep(delay)


def clear():
    sleep()
    os.system("cls" if os.name == "nt" else "clear")


def handle_quit():
    stop_backend()
    typing_effect(blue + f"Goodbye, Till next time!👋", reset)
    clear()
    exit()


def typing_effect(*message, delay=0.03):

    # Use .join for type-writer effect.
    message = "".join(message)
    for char in message:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()


def input_quit_handle(prompt, reset=Style.RESET_ALL):
    # Print in color
    print(prompt, reset, end="", flush=True)
    # Type in 'normal', color.
    user_input = input().strip().lower()

    if user_input in {"q", "quit"}:
        handle_quit()
    return user_input


def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")


def start_backend():
    global backend_process
    if backend_process is None:
        typing_effect(blue + f"Starting the Flask server,..." + reset)
        backend_process = subprocess.Popen(
            ["python", "backend.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        sleep(1)
    else:
        typing_effect(blue + "Backend server is already running." + reset)


def stop_backend():
    global backend_process

    if backend_process:
        typing_effect(blue + "Stopping the Flask backend server..." + reset)
        backend_process.terminate()
        backend_process.wait()
        backend_process = None
    else:
        typing_effect(blue + "Backend server is not running." + reset)


def log_login_time(log_collection, identifier, system_info):
    logs = find_documents(
        log_collection,
        (
            {"email": identifier}
            if log_collection == "admin_log"
            else {"name": identifier}
        ),
    )
    log = logs[-1] if logs else None

    login_times = (
        log.get("login_times", [])[-4:] if log else []
    )  # Default to empty list if no log
    login_times.append({"time": current_time()})

    if log:
        update_documents(
            log_collection,
            (
                {"email": identifier}
                if log_collection == "admin_log"
                else {"name": identifier}
            ),
            {"$set": {"login_times": login_times}},
        )
    else:
        print(blue + "Creating new login log entry..." + reset)
        update_documents(
            log_collection,
            (
                {"email": identifier}
                if log_collection == "admin_log"
                else {"name": identifier}
            ),
            {"$set": {"login_times": [login_times[-1]]}},
        )
