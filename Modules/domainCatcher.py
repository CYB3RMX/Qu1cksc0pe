#!/usr/bin/python3

import os
import sys
import warnings
from threading import Thread

# Module for natural language processing
try:
   import spacy
except:
   print("Error: >spacy< module not found.")
   sys.exit(1)

# Module for colors
try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# All strings
allStrings = open("temp.txt", "r").read().split('\n')

# Suppressing spacy warnings
warnings.filterwarnings("ignore")

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
magenta = Fore.LIGHTMAGENTA_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Handling language package
def LangNotFound():
   print(f"{errorS} Language package not found. Without this u wont be able to analyze strings.")
   choose = str(input("=> Should I install it for you [Y/n]?: "))
   if choose == 'Y' or choose == 'y':
      try:
         os.system("python3 -m spacy download en")
         print(f"{infoS} Language package downloaded.")
         sys.exit(0)
      except:
         print(f"{errorS} Program encountered an error.")
         sys.exit(1)
   else:
      print(f"{errorS} Without language package this module is wont work.")
      sys.exit(1)

# Handling url analyzing
def URLAnalyzer():
   # Our example url string
   ourUrl = "http://crl3.digicert.com"

   # Parsing string
   try:
      nlp = spacy.load("en")
      url = nlp(ourUrl)
   except:
      LangNotFound()

   # Lets scan!!
   for urls in allStrings:
      # Parsing and calculaing target string's similarity
      target = nlp(urls)
      if url.similarity(target) >= 0.3:
         if "http" in urls or "https" in urls:
            print(f"{cyan}({magenta}URL{cyan})->{white} {urls}")

# Handling ip address analyzing
def IPAddrAnalyzer():
   # Example ip shapes
   ipShapes = ['ddd.ddd.ddd.ddd', 'dd.ddd.ddd.ddd', 'd.ddd.ddd.ddd',
               'ddd.d.ddd.ddd', 'ddd.dd.ddd.ddd', 'ddd.ddd.d.ddd',
               'ddd.ddd.dd.ddd', 'ddd.ddd.ddd.d', 'ddd.ddd.ddd.dd',
               'd.d.d.d', 'dd.d.d.d', 'ddd.d.d.d', 'd.dd.d.d', 'd.ddd.d.d',
               'd.d.dd.d', 'd.d.ddd.d', 'd.d.d.dd', 'd.d.d.ddd', 'dd.dd.dd.dd',
               'd.dd.dd.dd', 'dd.d.dd.dd', 'dd.dd.d.dd', 'dd.dd.dd.d', 'ddd.ddd.d.d',
               'ddd.ddd.dd.dd', 'ddd.dd.dd.dd', 'ddd.ddd.d.dd', 'd.d.dd.dd']

   # Lets scan!!
   nlp = spacy.load("en")
   for ipaddr in allStrings:
      # Parsing target string's shapes
      targstr = nlp(ipaddr)
      for token in targstr:
         if str(token.shape_) in ipShapes:
            print(f"{cyan}({magenta}IP{cyan})->{white} {ipaddr}")

# Email address analyzing
def EmailCatcher():
   # Example email
   exEmail = "johnsmith@gmail.com"

   # Domains
   emDom = ['.to', '.ch', '.com', '.edu', '.gov', '.k12', '.us',
            '.pro', '.mo', '.ed', '.iupui']

   # Parsing string
   try:
      nlp = spacy.load("en")
      my_mail = nlp(exEmail)
   except:
      LangNotFound()
   
   # Scan zone
   for ems in allStrings:
      # Parsing string
      look = nlp(ems)
      if my_mail.similarity(look) >= 0.28:
         for ext in emDom:
            if ext in ems and "@" in ems:
               print(f"{cyan}({magenta}EMAIL{cyan})->{white} {ems}")

if __name__ == '__main__':
   print(f"{infoS} Qu1cksc0pe is analyzing this file for possible domain strings. It will take a while...\n")
   try:
      th1 = Thread(target=URLAnalyzer)
      th2 = Thread(target=IPAddrAnalyzer)
      th3 = Thread(target=EmailCatcher)
      th1.start()
      th2.start()
      th3.start()
   except:
      print(f"{errorS} An exception occured while analyzing file.")
      sys.exit(1)