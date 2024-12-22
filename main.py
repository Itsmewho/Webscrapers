from login.login import login
from login.reset_pass import reset_terminal
from login.unlock_account import unlock_terminal
from utils.helpers import (
    input_quit_handle,
    typing_effect,
    handle_quit,
    sleep,
    blue,
    green,
    reset,
    clear,
)


def main():
    # Testing:
    print(blue + "welcome to the testing ground!" + reset)

    while True:
        action = input_quit_handle(
            green + f"what do you wanna do? \n"
            "(1) Login\n"
            "(2) Reset password\n"
            "(3) Unlock Account\n"
            "(4) Exit\n"
            "Enter your choice: "
        ).strip()

        if action == "1":
            clear()
            login()
        elif action == "2":
            clear()
            reset_terminal()
        elif action == "3":
            clear()
            unlock_terminal()
        elif action == "6":
            handle_quit()
            break
        else:
            typing_effect("Invalid choice, please select again.")
            sleep()
            clear()


if __name__ == "__main__":
    main()
