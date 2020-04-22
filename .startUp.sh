#!/bin/bash

# colors
cy="\e[96m"
re="\e[91m"
gr="\e[92m"
wh="\e[0m"
ye="\e[93m"

# Update checker variable
version="22/04/2020"

banner()
{
  echo -en " $cy _____ _   _  __  _____  _   __ _____ _____ ___________ _____         ${gr}@ \n"
  echo -en " $cy|  _  | | | |/  |/  __ \| | / //  ___/  __ \  _  | ___ \  ___|      ${gr}@ @ @ \n"
  echo -en " $cy| | | | | | | | || /  \/| |/ / \  --.| /  \/ |/| | |_/ / |__       ${gr}@@ ${re}@ ${gr}@@ \n"
  echo -en " $cy| | | | | | | | || |    |    \   --. \ |   |  /| |  __/|  __|    ${gr}@@@${re}@@@@@${gr}@@@ \n"
  echo -en " $cy\ \/  / |_| |_| || \__/\| |\  \/\__/ / \__/\ |_/ / |   | |___      ${gr}@@ ${re}@ ${gr}@@ \n"
  echo -en "  $cy\_/\_|\___/ \___/\____/\_| \_/\____/ \____/\___/\_|   \____/       ${gr}@ @ @ \n"                                            
  echo -en "                                                                       @ \n"
  echo -en "                                        ${ye}|             | \n"
  echo -en "   ${wh}Suspicious file static-analysis tool.${ye}| ${wh}By CYB3RMX_${ye} | ${wh}Version: ${gr}1.6.1 \n"
  echo -en "   ${ye}-------------------------------------|             |${wh} \n\n"
  updateChecker
}
updateChecker()
{
   buffer=$(curl -sSL https://raw.githubusercontent.com/CYB3RMX/Qu1cksc0pe/master/README.md)
   echo $buffer | grep -o $version &>/dev/null
   if [ $? != 0 ];then
      echo -en "$cy[$re!$cy]$wh Looks like you need an update.\n\n"
   fi
}
# Execute functions
banner
