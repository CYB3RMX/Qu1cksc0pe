#!/bin/bash

# Colors
cyan='\e[96m'
red='\e[91m'
white='\e[0m'
green='\e[92m'

file=$1

command -v apktool > /dev/null 2>&1 || { echo >&2 '[!] Please install apktool to use this argument.'; exit 1; }

echo -en "$cyan[$red*$cyan]$white Analyzing: $green$file\n"
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
    cat AndroidManifest.xml | grep -o "android.permission.$perm"
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
