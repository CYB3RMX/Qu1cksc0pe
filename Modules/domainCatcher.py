#!/usr/bin/python3

import re
import sys

# Module for colors
try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# All strings
allStrings = open("temp.txt", "r").read().split('\n')

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
magenta = Fore.LIGHTMAGENTA_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Regex zone (Thanks to: https://github.com/dwisiswant0 for regex strings)
regex_dict = {
   "Amazon_AWS_Access_Key_ID": r"([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
   "Amazon_AWS_S3_Bucket": r"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
   "Discord_BOT_Token": r"((?:N|M|O)[a-zA-Z0-9]{23}\\.[a-zA-Z0-9-_]{6}\\.[a-zA-Z0-9-_]{27})$",
   "Facebook_Secret_Key": r"([f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K]|[f|F][b|B])(.{0,20})?['\"][0-9a-f]{32}",
   "Bitcoin_Wallet_Address": r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$",
   "Firebase": r"[a-z0-9.-]+\\.firebaseio\\.com",
   "GitHub": r"[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
   "Google_API_Key": r"AIza[0-9A-Za-z\\-_]{35}",
   "Heroku_API_Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
   "IP_Address": r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",
   "URL": r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
   "Monero_Wallet_Address": r"4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}",
   "Mac_Address": r"(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\\.]){2}[0-9A-Fa-f]{4})$",
   "Mailto": r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+"
}

# Main function
def RegexScanner():
   counter = 0
   print(f"{infoS} Qu1cksc0pe is analyzing this file for possible domain strings. Please wait...\n")
   for key in regex_dict:
      for targ in allStrings:
         try:
            match = re.findall(str(regex_dict[key]), str(targ))
            if match != []:
               print(f"{cyan}[{red}{key}{cyan}]>{white} {match[0]}")
               counter += 1
         except:
            continue
   if counter == 0:
      print(f"{errorS} Not any possible domain strings found.")

#Execution zone
RegexScanner()