# Simple executable packer detect script

# Colors
cyan="\e[96m"
red="\e[91m"
white="\e[0m"
yellow="\e[93m"

# Argument
targetFile=$1

# Wordlist
packers=$(cd Systems/keywords/; cat Packers.txt)

# Checker
checker=0

# function
lookPacker()
{
   echo -en "$cyan[$red*$cyan]$white Looking for packers...\n\n"
   for packs in ${packers[@]}
   do
      strings -a $targetFile | grep $packs &>/dev/null
      if [ $? -eq 0 ];then
	echo -en "$red=>$white This file migth be packed with $yellow$packs$white\n"
	checker=$((checker+1))
      fi
   done
   echo " "
   if [ $checker == 0 ];then
     echo -en "$cyan[$red!$cyan]$white Nothing found.\n"
   fi
   echo " "
}
lookPacker
