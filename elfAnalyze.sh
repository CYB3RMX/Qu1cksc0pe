#!/bin/bash

# Colors
cyan='\e[96m'
red='\e[91m'
white='\e[0m'
green='\e[92m'

command -v readelf > /dev/null 2>&1 || { echo >&2 '[!] Please install binutils to use this argument.'; exit 1; }

file=$1
echo -en "$cyan[$red*$cyan]$white Analyzing: $green$file\n"

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
