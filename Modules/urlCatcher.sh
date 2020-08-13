#!/bin/bash

# Colors
cyan="\e[1;96m"
red="\e[1;91m"
green="\e[1;92m"
default="\e[0m"

# This is for regex
regex_http='http://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
regex_https='https://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'

# Argument
targetFile=$1

# Look for urls
look()
{
   echo -en "$cyan[$red*$cyan]$default Looking for URLs...\n\n"
   strings -a $targetFile | grep -o "http://" &>/dev/null
   if [ $? -eq 0 ];then
      echo -en "$cyan[$red+$cyan]$default Found some HTTP URLs\n"
      urlFindHTTP
   else
      echo -en "$cyan[$red!$cyan]$default Nothing found about HTTP\n\n"
   fi
   strings -a $targetFile | grep -o "https://" &>/dev/null
   if [ $? -eq 0 ];then
      echo -en "$cyan[$red+$cyan]$default Found some HTTPS URLs\n"
      urlFindHTTPS
   else
      echo -en "$cyan[$red!$cyan]$default Nothing found about HTTPS\n"
      exit 1
   fi
}
# Parse urls
urlFindHTTP()
{
   # HTTP side
   echo -en "$red=>$green HTTP$default URls\n"
   echo -en "+------------------------------+\n"
   strings $targetFile | grep -o $regex_http
   echo -en "+------------------------------+\n\n"
}
urlFindHTTPS()
{
   # HTTPS side
   echo -en "$red=>$green HTTPS$default URLs\n"
   echo -en "+------------------------------+\n"
   strings $targetFile | grep -o $regex_https
   echo -en "+------------------------------+\n"
}

# Execute functions
look
