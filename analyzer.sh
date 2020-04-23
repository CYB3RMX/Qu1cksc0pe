#!/bin/bash

# Colors
cyan='\e[96m'
red='\e[91m'
white='\e[0m'
green='\e[92m'

file=$1

elflook()
{
  command -v readelf > /dev/null 2>&1 || { echo >&2 '[!] Please install binutils to use this argument.'; exit 1; }

  file $file | grep "ELF" &>/dev/null
  if [ $? -eq 0 ];then
     echo -en "$cyan[$red*$cyan]$white Analyzing: $green$file\n\n"

     symbols=$(cd Systems/Linux/; cat symbols.txt)
     sections=$(cd Systems/Linux/; cat sections.txt)
     segments=$(cd Systems/Linux/; cat segments.txt)
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
elflook
