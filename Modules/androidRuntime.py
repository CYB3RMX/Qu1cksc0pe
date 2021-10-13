#!/usr/bin/python3

import os
import sys
import time

try:
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import WordCompleter
except:
    print("Error: >prompt_toolkit< module not found.")
    sys.exit(1)

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

# Device manager
device_manager = frida.get_device_manager()
devices = device_manager.enumerate_devices()

def GetDevices(devices) -> list:
    # Tables
    devTable = PrettyTable()
    devTable.field_names = [
        f"{green}Number{white}", 
        f"{green}Device ID{white}", 
        f"{green}Device Name{white}", 
        f"{green}Connection Type{white}"
    ]

    # Parsing device informations
    if devices != []:
        count = 0
        numbers = []
        for dd in devices:
            devTable.add_row([count+1, dd.id, dd.name, dd.type])
            count += 1
            numbers.append(str(count))
        print(devTable)
        return numbers

def GetPackages(index) -> list:
    # Tables
    appTable = PrettyTable()
    appTable.field_names = [
        f"{green}Application Name{white}",
        f"{green}Package Name{white}"
    ]

    # Parsing application informations
    try:
        applications = devices[int(index)-1].enumerate_applications()
        package_list = []
        for app in applications:
            appTable.add_row([app.name, app.identifier])
            package_list.append(app.identifier)
        print(appTable)
        return package_list
    except frida.ServerNotRunningError:
        print(f"{errorS} Unable to connect to remote frida-server.\n")
        sys.exit(1)

def GetScripts() -> list:
    # Tables
    scriptTable = PrettyTable()
    scriptTable.field_names = [
        f"{green}Description{white}",
        f"{green}File Name{white}"
    ]

    # Gathering and parsing script files
    menu_content = os.listdir(f"{sc0pe_path}/Systems/Android/FridaScripts/")
    sc_list = []
    for sc in menu_content:
        scname = sc.replace("-", " ")
        scriptTable.add_row([scname.replace(".js", "").upper(), sc.replace(".js", "")])
        sc_list.append(sc.replace(".js", ""))
    print(scriptTable)
    return sc_list

def FridaMain():
    try:
        # Device enumeration
        print(f"{infoS} Enumerating devices...")
        device_completer = WordCompleter(GetDevices(devices))
        device_index = prompt("\n>>> Select a device: ", completer=device_completer)

        # Enumerating installed applications
        print(f"\n{infoS} Enumerating installed applications...")
        app_completer = WordCompleter(GetPackages(index=device_index))
        target_application = prompt("\n>>> Enter package name: ", completer=app_completer)

        # Script menu
        print(f"\n{infoS} Gathering available FRIDA scripts...")
        script_completer = WordCompleter(GetScripts())
        use_script = prompt("\n>>> Enter file name: ", completer=script_completer)
    except:
        print(f"{errorS} Program terminated.")
        sys.exit(1)

    # Process management
    try:
        process = devices[int(device_index)-1].spawn([target_application])
        devices[int(device_index)-1].resume(process)
        time.sleep(1)
    except frida.NotSupportedError:
        print(f"{errorS} An error occured while attach on remote device. Is frida-server running on remote device?\n")
        sys.exit(1)

    # Session handling
    session = devices[int(device_index)-1].attach(process)
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