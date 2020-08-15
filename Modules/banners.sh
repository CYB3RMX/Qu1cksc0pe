#!/bin/bash

# colors
cy="\e[1;96m"
re="\e[1;91m"
gr="\e[1;92m"
wh="\e[0m"
ye="\e[1;93m"
ma="\e[1;95m"

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
  echo -en "   ${wh}Suspicious file static-analysis tool.${ye}| ${wh}By CYB3RMX_${ye} | ${wh}Version: ${gr}1.6.7 \n"
  echo -en "   ${ye}-------------------------------------|             |${wh} \n\n"
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
  echo -en "$ma  NMM-  sMMyvvvvvvvvvvvvvvsMMy  .MMM   $wh|       ${gr}Version$wh:$ye 1.6.7         $wh|\n"
  echo -en "$ma  ooo.  :ooooooo+    +ooooooo/   ooo   $wh+------------|||||||-----------+\n"
  echo -en "$ma           /MMMMN    mMMMM+                        $wh |||||||            \n"
  echo -en "                                                    |||||||            \n\n"
}
banner2()
{
  echo -en "            ______ \n"
  echo -en "         .--      --. \n"
  echo -en "       ./            \\ \n"
  echo -en "      /                \ \n"
  echo -en "     ;   Qu1cksc0pe    ;; \n"
  echo -en "     |                 |;  \n"
  echo -en "     ;     v1.6.7      ;| \n"
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
}
banner3()
{
  echo -en "                   <------------------------------------------>\n"
  echo -en "                   <  This tool is very dangerous. Be careful >\n"
  echo -en "$gr           __      $wh<   while using it!!                       >\n"
  echo -en "$gr         _|  |_    $wh<------------------------------------------>\n"
  echo -en "$gr       _|      |_  $wh /\n"
  echo -en "$gr      |  _    _  | $wh/\n"
  echo -en "$gr      | |_|  |_| | \n"
  echo -en "   _  |  _    _  |  _ \n"
  echo -en "  |_|_|_| |__| |_|_|_| \n"
  echo -en "    |_|_        _|_|   $wh<- Mr. Virus\n"
  echo -en "$gr      |_|      |_|$wh \n\n"
}
banner4()
{
  echo -en "\n$ye+ ------------------------------ + \n"
  echo -en "I                                I \n"
  echo -en "I      ${wh}*********************     ${ye}I\n"
  echo -en "I      ${wh}*  ${re}MALWARE ALERT!!  ${wh}*     ${ye}I\n"
  echo -en "I      ${wh}*********************     ${ye}I\n"
  echo -en "I                                I \n"
  echo -en "+ --------------I I------------- + \n"
  echo -en "                I I                 ${gr}___QU1CKSC0PE___\n"
  echo -en "                ${ye}I I \n"
  echo -en "             ____V_____              ${gr}Version:$re 1.6.7$wh\n\n\n"
}

# Execute functions
randomStart=$(( RANDOM % 5 ))
case $randomStart in
	0) banner ;;
	1) banner1 ;;
	2) banner2 ;;
	3) banner3 ;;
	4) banner4 ;;
esac
