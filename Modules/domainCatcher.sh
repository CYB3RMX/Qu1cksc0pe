#!/bin/bash

# Colors
cyan="\e[1;96m"
red="\e[1;91m"
green="\e[1;92m"
default="\e[0m"

# This is for regex
regex_ip='\(25[0-5]\|2[0-4][0-9]\|[01][0-9][0-9]\|[0-9][0-9]\)\.\(25[0-5]\|2[0-4][0-9]\|[01][0-9][0-9]\|[0-9][0-9]\)\.\(25[0-5]\|2[0-4][0-9]\|[01][0-9][0-9]\|[0-9][0-9]\)\.\(25[0-5]\|2[0-4][0-9]\|[01][0-9][0-9]\|[0-9][0-9]\)'

# Argument
targetFile=$1

# Look for urls
lookUrl()
{
   echo -en "$cyan[$red*$cyan]$default Looking for URLs...\n\n"
   strings --all $targetFile | grep -Eo '(http|https)://[^/"]+' &>/dev/null
   if [ $? -eq 0 ];then
      strings --all $targetFile | grep -Eo '(http|https)://[^/"]+'
   else
      echo -en "$cyan[$red!$cyan]$default Nothing found about URL's\n\n"
   fi
}

# look for IP Addresses
lookIp()
{
   echo -en "\n$cyan[$red*$cyan]$default Looking for IP addresses...\n\n"
   strings --all $targetFile | grep $regex_ip &>/dev/null
   if [ $? -eq 0 ];then
      strings --all $targetFile | grep $regex_ip
   else
      echo -en "$cyan[$red!$cyan]$default Not any IP addresses found.\n"
      exit 1
   fi
}

# Execute functions
lookUrl
lookIp