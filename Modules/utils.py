import sys


def user_confirm(question_text):
    return str(input(question_text)).lower() == "y"

def err_exit(message, arg_override=1):
    print(message)
    sys.exit(arg_override)
