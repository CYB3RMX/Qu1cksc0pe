import os
import sys


def user_confirm(question_text):
    return str(input(question_text)).lower() == "y"

def err_exit(message):
    print(message)
    sys.exit(1)