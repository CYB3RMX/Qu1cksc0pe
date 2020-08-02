#!/bin/bash

# Colors
cyan="\e[96m"
red="\e[91m"
white="\e[0m"

# Wordlists
sectionz=$(cd Systems/Linux/; cat sections.txt)
segmentz=$(cd Systems/Linux/; cat segments.txt)

# Defining function
lookFor()
{
   echo -en "$cyan[$red+$cyan]$white Sections\n"
   echo -en "+------------------------------+\n"
   for sec in ${sectionz[@]}
   do
       cat Modules/elves.txt | grep -o "$sec" &>/dev/null
       if [ $? -eq 0 ];then
	  echo -en "$red=>$white $sec\n"
       fi
   done
   echo -en "+------------------------------+\n\n"

   echo -en "$cyan[$red+$cyan]$white Segments\n"
   echo -en "+------------------------------+\n"
   for seg in ${segmentz[@]}
   do
       cat Modules/elves.txt | grep -o "$seg" &>/dev/null
       if [ $? -eq 0 ];then
	  echo -en "$red=>$white $seg\n"
       fi
   done
   echo -en "+------------------------------+\n\n"
}

# Executing
lookFor
rm -rf Modules/elves.txt
