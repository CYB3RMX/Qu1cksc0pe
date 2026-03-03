import os

# Persistent, user-writable location for the sc0pe_path cache.
# Using the home directory avoids PermissionError when the current
# working directory is root-owned (e.g. after a deb installation).
PATH_HANDLER_FILE = os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path")
