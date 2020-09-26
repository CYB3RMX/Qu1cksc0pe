#!/bin/bash

# Colors
cyan="\e[1;96m"
red="\e[1;91m"
green="\e[1;92m"
default="\e[0m"

# This is for regex
regex_http='http://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
regex_https='https://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
regex_ip='\(25[0-5]\|2[0-4][0-9]\|[01][0-9][0-9]\|[0-9][0-9]\)\.\(25[0-5]\|2[0-4][0-9]\|[01][0-9][0-9]\|[0-9][0-9]\)\.\(25[0-5]\|2[0-4][0-9]\|[01][0-9][0-9]\|[0-9][0-9]\)\.\(25[0-5]\|2[0-4][0-9]\|[01][0-9][0-9]\|[0-9][0-9]\)'

# Argument
targetFile=$1

# Look for urls
lookUrl()
{
   echo -en "$cyan[$red*$cyan]$default Looking for URLs...\n\n"
   strings --all $targetFile | grep -o "http://" &>/dev/null
   if [ $? -eq 0 ];then
      urlFindHTTP
   else
      echo -en "$cyan[$red!$cyan]$default Nothing found about HTTP\n\n"
   fi
   strings --all $targetFile | grep -o "https://" &>/dev/null
   if [ $? -eq 0 ];then
      urlFindHTTPS
   else
      echo -en "$cyan[$red!$cyan]$default Nothing found about HTTPS\n"
   fi
}

# look for IP Addresses
lookIp()
{
   echo -en "\n$cyan[$red*$cyan]$default Looking for IP addresses...\n\n"
   strings --all $targetFile | grep $regex_ip &>/dev/null
   if [ $? -eq 0 ];then
      ipAddrHunter
   else
      echo -en "$cyan[$red!$cyan]$default Not any IP addresses found.\n"
      exit 1
   fi
}
# Parse urls
urlFindHTTP()
{
   # HTTP side
   echo -en "$red=>$default Extracted$green HTTP$default URLs\n"
   echo -en "+-----------------------------------+\n"
   strings --all $targetFile | grep -o $regex_http
   echo -en "+-----------------------------------+\n\n"
}
urlFindHTTPS()
{
   # HTTPS side
   echo -en "$red=>$default Extracted$green HTTPS$default URLs\n"
   echo -en "+-----------------------------------+\n"
   strings --all $targetFile | grep -o $regex_https
   echo -en "+-----------------------------------+\n"
}

# Parse IP addresses
ipAddrHunter()
{
   echo -en "$red=>$default Extracted$green IP Addresses$default\n"
   echo -en "+------------------------------+\n"
   strings --all $targetFile | grep $regex_ip
   echo -en "+------------------------------+\n"
}

# Execute functions
lookUrl
lookIp