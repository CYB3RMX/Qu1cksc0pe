#!/usr/bin/python3

import sys
import random

from .utils import err_exit

# Module for colors
try:
    from rich import print
except:
    err_exit("Error: >rich< module not found.")

# Colors
re = "[bold red]"
cy = "[bold cyan]"
wh = "[white]"
gr = "[bold green]"
ma = "[bold magenta]"
ye = "[bold yellow]"
bl = "[bold blue]"

banner1 = f"""
 {cy}_____ _   _  __  _____  _   __ _____ _____ ___________ _____         {gr}@
{cy}|  _  | | | |/  |/  __ \\| | / //  ___/  __ \\  _  | ___ \\  ___|      {gr}@ @ @
{cy}| | | | | | | | || /  \\/| |/ / \\  --.| /  \\/ |/| | |_/ / |__       {gr}@@ {re}@ {gr}@@
{cy}| | | | | | | | || |    |    \\   --. \\ |   |  /| |  __/|  __|    {gr}@@@{re}@@@@@{gr}@@@
{cy}\\  \\/ / |_| |_| || \\__/\\| |\\  \\/\\__/ / \\__/\\ |_/ / |   | |___      {gr}@@ {re}@ {gr}@@
{cy} \\_/\\_|\\___/ \\___/\\____/\\_| \\_/\\____/ \\____/\\___/\\_|   \\____/       {gr}@ @ @
                                                                      @
                                   {ye}|             |
  {wh}All in One malware analysis tool.{ye}| {wh}By CYB3RMX_ {ye}| {wh}Version: {gr}1.8.5
  {ye}---------------------------------|             |{wh}\n
"""
banner2=f"""
        {ma}:ooooo/        /ooooo:
           +MMd^^^^^^^^hMMo
        oNNNMMMNNNNNNNNMMMNNNs
     /oodMMdooyMMMMMMMMyoodMMdoo/      {wh}+-----------------------------------------+
   {ma}..dMMMMMy. :MMMMMMMM/  sMMMMMm..    {wh}|              {gr}Qu1cksc0pe                 {wh}|
  {ma}dmmMMMMMMNmmNMMMMMMMMNmmNMMMMMMmmm   {wh}|                                         |
  {ma}NMMyoodMMMMMMMMMMMMMMMMMMMMdoosMMM   {wh}|    {gr}All in One malware analysis tool.    {wh}|
  {ma}NMM-  sMMMNNNNNNNNNNNNNNNMMy  .MMM   {wh}|                                         |
  {ma}NMM-  sMMyvvvvvvvvvvvvvvsMMy  .MMM   {wh}|             {gr}Version{wh}: {ye}1.8.5              {wh}|
  {ma}ooo.  :ooooooo+    +ooooooo/   ooo   {wh}+-----------------|||||||-----------------+
           {ma}/MMMMN    mMMMM+                              {wh}|||||||
                                                         |||||||\n
"""
banner3=f"""
                   {wh}<------------------------------------------>
                   <  This tool is very dangerous. Be careful >
           {gr}__      {wh}<   while using it!!                       >
         {gr}_|  |_    {wh}<------------------------------------------>
       {gr}_|      |_   {wh}/
      {gr}|  _    _  | {wh}/
      {gr}| |_|  |_| |
   _  |  _    _  |  _
  |_|_|_| |__| |_|_|_|
    |_|_        _|_|   {wh}<- Mr. Virus
      {gr}|_|      |_|{wh} \n
"""
banner4=f"""
\n{ye}+ ------------------------------ +
I                                I
I      {wh}*********************     {ye}I
I      {wh}*  {re}MALWARE ALERT!!  {wh}*     {ye}I
I      {wh}*********************     {ye}I
I                                I
+ --------------I I------------- +
                I I                 {gr}___QU1CKSC0PE___
                {ye}I I
             ____V_____              {ma}Version: {re}1.8.5{wh}\n\n
"""
banner5=f"""
                        {re}* -------------------------------- *
           {gr}__           {re}| {gr}Name: {wh}Mr. Virus                  {re}|
         {gr}_|  |_         {re}| {gr}Type: {wh}Trojan.Dropper             {re}|
       {gr}_|      |_       {re}| {gr}Status: {wh}Qu1cksc0ped!!            {re}|
      {gr}|          |      {re}| {gr}Description: {wh}He said dont use    {re}|
      {gr}|  {re}X    X  {gr}|      {re}| {wh}this tool. Now he is dead.       {re}|
   {gr}_  |  _    _  |  _   {re}* -------------------------------- *
  {gr}|_|_|_| |__| |_|_|_|
    |_|_        _|_|
      |_|      |_|{wh} \n
"""
banner6=f"""
\n{cy}SIMON SAYS:\n
         {gr}-o          o-
          +hydNNNNdyh+          {wh}<--------------------------->
        {gr}+mMMMMMMMMMMMMm+        {wh}<  Do not click every link. >
       {gr}dMM{wh}m:{gr}NMMMMMMN{wh}:m{gr}MMb       {wh}<      Please listen me!!   >
      {gr}hMMMMMMMMMMMMMMMMMMh      {wh}<--------------------------->
  {gr}..  yyyyyyyyyyyyyyyyyyyy  ..    {wh}/
{gr}.mMMm MMMMMMMMMMMMMMMMMMMM mMMm. {wh}/
{gr}:MMMM-MMMMMMMMMMMMMMMMMMMM-MMMM:
:MMMM-MMMMMMMMMMMMMMMMMMMM-MMMM:
:MMMM-MMMMMMMMMMMMMMMMMMMM-MMMM:
:MMMM-MMMMMMMMMMMMMMMMMMMM-MMMM:
-MMMM-MMMMMMMMMMMMMMMMMMMM-MMMM-
 +yy+ MMMMMMMMMMMMMMMMMMMM +yy+  {wh}<- Mr. Simon
      {gr}mMMMMMMMMMMMMMMMMMMm
       /++MMMMh++hMMMM++/
          MMMMo  oMMMM
          MMMMo  oMMMM
          oNMm-  -mMNs{wh} \n
"""
banner7=f"""
\n  .-------------------------------------.
  | [____{re}DOWNLOADING FREE RTX 5090{wh}____] |
  |  _________________________________  |
  | |{gr}:::::::::::::::::{wh}60%{gr}|{wh}            | |
  |  \"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"  |
  |_____________________________________|\n
"""
banner8=f"""
{gr}                            .oodMMMM
                   .oodMMMMMMMMMMMMM
{re}       ..oodMMM{gr}  MMMMMMMMMMMMMMMMMMM
{re} oodMMMMMMMMMMM{gr}  MMMMMMMMMMMMMMMMMMM
{re} MMMMMMMMMMMMMM{gr}  MMMMMMMMMMMMMMMMMMM
{re} MMMMMMMMMMMMMM{gr}  MMMMMMMMMMMMMMMMMMM        {wh}One day Windows will be {gr}MALWAREPROOF{wh}...
{re} MMMMMMMMMMMMMM{gr}  MMMMMMMMMMMMMMMMMMM
{re} MMMMMMMMMMMMMM{gr}  MMMMMMMMMMMMMMMMMMM
{re} MMMMMMMMMMMMMM{gr}  MMMMMMMMMMMMMMMMMMM                      {wh}Just kidding XDD
					    
{cy} MMMMMMMMMMMMMM{ye}  MMMMMMMMMMMMMMMMMMM
{cy} MMMMMMMMMMMMMM{ye}  MMMMMMMMMMMMMMMMMMM
{cy} MMMMMMMMMMMMMM{ye}  MMMMMMMMMMMMMMMMMMM
{cy} MMMMMMMMMMMMMM{ye}  MMMMMMMMMMMMMMMMMMM
{cy} MMMMMMMMMMMMMM{ye}  MMMMMMMMMMMMMMMMMMM
{cy} `^^^^^^MMMMMMM{ye}  MMMMMMMMMMMMMMMMMMM
{cy}       ````^^^^{ye}  ^^MMMMMMMMMMMMMMMMM
                      ````^^^^^^MMMM{wh}
"""
banner9=f"""
       {re}_______________
      |{cy}@@@@{re}|     |{cy}####{re}|
      |{cy}@@@@{re}|     |{cy}####{re}|
      |{cy}@@@@{re}|     |{cy}####{re}|
      \\\\{cy}@@@@{re}|     |{cy}####{re}/
       \\\\{cy}@@@{re}|     |{cy}###{re}/
        `{cy}@@{re}|_____|{cy}##{re}'
             {ma}(O)
        {ye}.-''''''''''-.             {gr}Congratulations!{ye}
      .'  * * * * * * `.
     :  *             * :                  {gr}You just analyzed your 1000th sample :){ye}
    : ~ Malware Hunter ~ :
    :         of         :
    :    ~ The Year ~    :             {gr}You won 100BTC!!!{ye}
     :  *             * :
      `.  * * * * * * .'
        `-..........-'
"""
banner10=f"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣤⣶⣶⣿⣷⣆⠀⠀⠀⠀
⠀⠀⠀⢀⣤⣤⣶⣶⣾⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⡆⠀⠀⠀
⠀⢀⣴⣿⣿⣿⣿⣿⣿⡿⠛⠉⠉⠀⠀⠀⣿⣿⣿⣿⣷⠀⠀⠀        {ye}!!WARNING!!{wh}: Press {re}F key{wh} to respect who clicked this link:
⣠⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⢤⣶⣾⠿⢿⣿⣿⣿⣿⣇⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠈⠉⠀⠀⠀⣿⣿⣿⣿⣿⡆⠀                  -->  {gr}https://youtu.be/dQw4w9WgXcQ{wh}
⢸⣿⣿⣿⣏⣿⣿⣿⣿⣿⣷⠀⠀⢠⣤⣶⣿⣿⣿⣿⣿⣿⣿⡀
⠀⢿⣿⣿⣿⡸⣿⣿⣿⣿⣿⣇⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣧
⠀⠸⣿⣿⣿⣷⢹⣿⣿⣿⣿⣿⣄⣀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿
⠀⠀⢻⣿⣿⣿⡇⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⠀⠀⠘⣿⣿⣿⣿⠘⠻⠿⢛⣛⣭⣽⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿
⠀⠀⠀⢹⣿⣿⠏⠀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠋
⠀⠀⠀⠈⣿⠏⠀⣰⣿⣿⣿⣿⣿⣿⠿⠟⠛⠋⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⡿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

randomBanner = random.randint(1, 10)
if randomBanner == 1:
    print(banner1)
elif randomBanner == 2:
    print(banner2)
elif randomBanner == 3:
    print(banner3)
elif randomBanner == 4:
    print(banner4)
elif randomBanner == 5:
    print(banner5)
elif randomBanner == 6:
    print(banner6)
elif randomBanner == 7:
    print(banner7)
elif randomBanner == 8:
    print(banner8)
elif randomBanner == 9:
    print(banner9)
elif randomBanner == 10:
    print(banner10)
else:
    pass
