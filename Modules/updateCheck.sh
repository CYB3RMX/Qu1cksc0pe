#!/bin/bash

# colors
cy="\e[96m"                                                                 re="\e[91m"
gr="\e[92m"                                                                 wh="\e[0m"

# Update checker variable
version="06/08/2020"

updateChecker()                                                             {                                                                              echo -en "$cy[$re*$cy]$wh Checking updates...\n"
   buffer=$(curl -sSL https://raw.githubusercontent.com/CYB3RMX/Qu1cksc0pe/master/README.md)
   echo $buffer | grep -o $version &>/dev/null
   if [ $? != 0 ];then
      echo -en "$cy[$re!$cy]$wh STATE: ${re}Outdated$wh.\n"
      echo -en "$cy[$re*$cy]$wh Installing new updates...\n"
      git pull &>/dev/null
      if [ $? -eq 0 ];then
	echo -en "$cy[$re+$cy]$wh Installation completed.\n"
      fi
   else
      echo -en "$cy[$re*$cy]$wh STATE: ${gr}Up to date$wh.\n"
   fi
}
updateChecker
