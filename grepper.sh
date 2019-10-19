#!/bin/bash

# Colors
cyan='\e[96m'
red='\e[91m'
green='\e[92m'
default='\e[0m'
yellow='\e[93m'

# Arguments
target=$1
wordz=$2

strings $target | grep "${wordz}" &>/dev/null
if [ $? -eq 0 ];then
  echo -en "$red=>$default Found: ${green}$wordz$default\n"
fi
