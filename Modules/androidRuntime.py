#!/usr/bin/python3

import os
import sys
import time

try:
    import frida
except:
    print("Error: >frida< module not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX
magenta = Fore.LIGHTMAGENTA_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

def FridaMain():
    # Tables!!
    devTable = PrettyTable()
    devTable.field_names = [
        f"{green}Number{white}", 
        f"{green}Device ID{white}", 
        f"{green}Device Name{white}", 
        f"{green}Connection Type{white}"
    ]
    appTable = PrettyTable()
    appTable.field_names = [
        f"{green}Application Name{white}",
        f"{green}Package Name{white}"
    ]
    scriptTable = PrettyTable()
    scriptTable.field_names = [
        f"{green}Description{white}",
        f"{green}File Name{white}"
    ]

    # Device enumeration
    print(f"{infoS} Enumerating devices...")
    device_manager = frida.get_device_manager()
    devices = device_manager.enumerate_devices()
    if devices != []:
        count = 0
        for dd in devices:
            devTable.add_row([count, dd.id, dd.name, dd.type])
            count += 1
        print(devTable)

    # Select target device
    device_index = int(input(f"\n{magenta}>>>{white} Select a device: "))

    # Enumerating installed applications
    print(f"\n{infoS} Enumerating installed applications...")
    try:
        applications = devices[device_index].enumerate_applications()
        for app in applications:
            appTable.add_row([app.name, app.identifier])
        print(appTable)
    except frida.ServerNotRunningError:
        print(f"{errorS} Unable to connect to remote frida-server.")
        sys.exit(1)

    # Select target application
    target_application = str(input(f"\n{magenta}>>>{white} Enter package name: "))

    # Script menu
    print(f"\n{infoS} Gathering available FRIDA scripts...")
    menu_content = os.listdir(f"{sc0pe_path}/Systems/Android/FridaScripts/")
    for sc in menu_content:
        scname = sc.replace("-", " ")
        scriptTable.add_row([scname.replace(".js", "").upper(), sc.replace(".js", "")])
    print(scriptTable)
    use_script = str(input(f"\n{magenta}>>>{white} Enter file name: "))

    # Process management
    try:
        process = devices[device_index].spawn([target_application])
        devices[device_index].resume(process)
        time.sleep(1)
    except frida.NotSupportedError:
        print(f"{errorS} An error occured while attach on remote device. Is frida-server running on remote device?")
        sys.exit(1)

    # Session handling
    session = devices[device_index].attach(process)
    script = session.create_script(open(f"{sc0pe_path}/Systems/Android/FridaScripts/{use_script}.js").read())
    script.load()
    while True:
        if session.is_detached is False:
            input()
        else:
            print(f"{errorS} Process detached.")
            sys.exit(1)

# Execution
FridaMain()