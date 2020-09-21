#!/bin/bash

# Colors
cyan="\e[1;96m"
red="\e[1;91m"
white="\e[0m"

# Regex zone
regex_emails='[[:alnum:]]\+@[[:alnum:]]\+.[[:alnum:]]\+'
regex_http='http://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'   
regex_https='https://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]' 

# Wordlists
interesting=$(cd Systems/Android/; cat suspicious.txt)

# Defining analyzer
lookStr()
{
  # Hunting interesting strings
  counter=0
  echo -en "$cyan[$red*$cyan]$white Extracting interesting ones...\n"
  for ints in ${interesting[@]}
   do
       cat apkStr.txt | grep "$ints" &>/dev/null
       if [ $? -eq 0 ];then
          echo -en "$red=>$white $ints\n"
	  counter=$((counter+1))
       fi
   done
   if [ $counter == 0 ];then
      echo -en "$cyan[$red!$cyan]$white Nothing found.\n"
   fi

   # Hunting email addresses
   echo -en "\n$cyan[$red*$cyan]$white Extracting email addresses...\n"
   cat apkStr.txt | grep -o $regex_emails &>/dev/null
   if [ $? -eq 0 ];then
      cat apkStr.txt | grep -o $regex_emails
   else
      echo -en "$cyan[$red!$cyan]$white Not any email addresses found.\n"
   fi

   # Hunting domains
   echo -en "\n$cyan[$red*$cyan]$white Extracting domains...\n"
   cat apkStr.txt | grep -o $regex_http &>/dev/null
   if [ $? -eq 0 ];then
      cat apkStr.txt | grep -o $regex_http
   fi
   cat apkStr.txt | grep -o $regex_https &>/dev/null
   if [ $? -eq 0 ];then
      cat apkStr.txt | grep -o $regex_https
   else
      echo -en "$cyan[$red!$cyan]$white Not any domains found.\n"
   fi
}

# Execution
lookStr
rm apkStr.txt