# frequent use
import os, time
from datetime import datetime
from colorama import Style, Fore

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


def input_quit_handle(prompt, reset=Style.RESET_ALL, lowercase=False):
    # Print in color
    print(prompt, reset, end="", flush=True)
    # Type in 'normal', color.
    user_input = input().strip()

    if lowercase:
        user_input = user_input.lower()

    if user_input in {"q", "quit"}:
        handle_quit()
    return user_input


def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
