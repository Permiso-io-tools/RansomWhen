from termcolor import colored

def printOutput(message, type, verbose=False):
    if type == "failure":
        print(
            colored(
                f"[*] {message}!", "red", attrs=['bold']
            )
        )
    if verbose:
        if type == "loading":
            print(
                colored(
                    f"[*] {message}...", "yellow", attrs=['bold']
                )
            )
        elif type == "success":
            print(
                colored(
                    f"[*] {message}!", "green", attrs=['bold']
                )
            )

