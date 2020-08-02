#!/bin/bash

# colors
cy="\e[96m"
re="\e[91m"
gr="\e[92m"
wh="\e[0m"
ye="\e[93m"
ma="\e[95m"

# Update checker variable
version="02/08/2020"

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
  echo -en "   ${wh}Suspicious file static-analysis tool.${ye}| ${wh}By CYB3RMX_${ye} | ${wh}Version: ${gr}1.6.5 \n"
  echo -en "   ${ye}-------------------------------------|             |${wh} \n\n"
  updateChecker
}
banner1()
{
  echo -en "$ma        :ooooo/        /ooooo:      \n"
  echo -en "           +MMd^^^^^^^^hMMo         \n"
  echo -en "        oNNNMMMNNNNNNNNMMMNNNs      \n"
  echo -en "     /oodMMdooyMMMMMMMMyoodMMdoo/      $wh+------------------------------+\n"
  echo -en "$ma   ..dMMMMMy. :MMMMMMMM/  sMMMMMm..    $wh|         ${gr}Qu1cksc0pe           $wh|\n"
  echo -en "$ma  dmmMMMMMMNmmNMMMMMMMMNmmNMMMMMMmmm   $wh|                              |\n"
  echo -en "$ma  NMMyoodMMMMMMMMMMMMMMMMMMMMdoosMMM   $wh| ${gr}Malware static analysis tool.$wh|\n"
  echo -en "$ma  NMM-  sMMMNNNNNNNNNNNNNNNMMy  .MMM   $wh|                              |\n"
  echo -en "$ma  NMM-  sMMyvvvvvvvvvvvvvvsMMy  .MMM   $wh|       ${gr}Version$wh:$ye 1.6.5         $wh|\n"
  echo -en "$ma  ooo.  :ooooooo+    +ooooooo/   ooo   $wh+------------|||||||-----------+\n"
  echo -en "$ma           /MMMMN    mMMMM+                        $wh |||||||            \n"
  echo -en "                                                    |||||||            \n\n"
  updateChecker
}
banner2()
{
  echo -en "            ______ \n"
  echo -en "         .--      --. \n"
  echo -en "       ./            \\ \n"
  echo -en "      /                \ \n"
  echo -en "     ;   Qu1cksc0pe    ;; \n"
  echo -en "     |                 |;  \n"
  echo -en "     ;     v1.6.5      ;| \n"
  echo -en "     ;\               / ; \n"
  echo -en "      \ .           .  / \n"
  echo -en "        . -._____.-  . \n"
  echo -en "         / / _____.- \n"
  echo -en "        / / / \n"
  echo -en "       / / / \n"
  echo -en "      / / / \n"
  echo -en "     / / / \n"
  echo -en "    / / / \n"
  echo -en "   / / / \n"
  echo -en "  / / / \n"
  echo -en " / / / \n"
  echo -en "/ / / \n"
  echo -en "\/_/ \n\n"
  updateChecker
}
updateChecker()
{
   echo -en "$cy[$re*$cy]$wh Checking updates...\n"
   buffer=$(curl -sSL https://raw.githubusercontent.com/CYB3RMX/Qu1cksc0pe/master/README.md)
   echo $buffer | grep -o $version &>/dev/null
   if [ $? != 0 ];then
      echo -en "$cy[$re!$cy]$wh STATE: ${re}Outdated$wh.\n\n"
   else
      echo -en "$cy[$re*$cy]$wh STATE: ${gr}Up to date$wh.\n\n"
   fi
}
# Execute functions
randomStart=$(( RANDOM % 3 ))
case $randomStart in
	0) banner ;;
	1) banner1 ;;
	2) banner2 ;;
esac
