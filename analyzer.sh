#!/bin/bash

# Colors
cyan='\e[96m'
red='\e[91m'
white='\e[0m'
green='\e[92m'

args=$1
file=$2

apklook()
{
  command -v apktool > /dev/null 2>&1 || { echo >&2 '[!] Please install apktool to use this argument.'; exit 1; }

  echo -en "$cyan[$red*$cyan]$white Analyzing: $green$file\n\n"
  apktool d $file &>/dev/null

  name=$(echo -n "$file" | wc -c)
  limit=$(($name-4))
  temp=$(echo $file | cut -c 1-$limit)
  permission=$(cd keywords/; cat permissions.txt)
  hpermission=$(cd keywords/; cat hardware.txt)

  cd $temp/
  echo -en "$cyan[$red+$cyan]$white Permissions\n"
  echo "+------------------------------+"
  for perm in ${permission[@]}
  do
      cat AndroidManifest.xml | grep -o "$perm"
  done
  echo "+------------------------------+"
  echo -en "\n$cyan[$red+$cyan]$white Hardware permissions\n"
  echo "+------------------------------+"
  for hperm in ${hpermission[@]}
  do
      cat AndroidManifest.xml | grep -o "android.hardware.$hperm"
  done
  echo "+------------------------------+"
  cd ../
  rm -rf $temp
}
elflook()
{
  command -v readelf > /dev/null 2>&1 || { echo >&2 '[!] Please install binutils to use this argument.'; exit 1; }

  file $file | grep "ELF" &>/dev/null
  if [ $? -eq 0 ];then
     echo -en "$cyan[$red*$cyan]$white Analyzing: $green$file\n\n"

     symbols=$(cd keywords/; cat symbols.txt)
     sections=$(cd keywords/; cat sections.txt)
     segments=$(cd keywords/; cat segments.txt)
     fileStrings=$(readelf -a $file)

     echo -en "$cyan[$red+$cyan]$white Symbols\n"
     echo "+------------------------------+"
     for sym in ${symbols[@]}
     do
        echo $fileStrings | grep -o "$sym" &>/dev/null
        if [ $? -eq 0 ];then
           echo -en "$red=>$white $sym\n"
        fi
     done
     echo "+------------------------------+"
     echo -en "\n$cyan[$red+$cyan]$white Sections\n"
     echo "+------------------------------+"
     for sec in ${sections[@]}
     do
        echo $fileStrings | grep -o "$sec" &>/dev/null
        if [ $? -eq 0 ];then
           echo -en "$red=>$white $sec\n"
        fi
     done
     echo "+------------------------------+"
     echo -en "\n$cyan[$red+$cyan]$white Segments\n"
     echo "+------------------------------+"
     for seg in ${segments[@]}
     do
        echo $fileStrings | grep -o "$seg" &>/dev/null
        if [ $? -eq 0 ];then
           echo -en "$red=>$white $seg\n"
        fi
     done
     echo "+------------------------------+"
  else
     echo -en "$cyan[${red}!$cyan]$white Target file is not ELF file.\n"
  fi
}
case $args in
  --apk) apklook ;;
  --elf) elflook ;;
esac
