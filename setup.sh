#! /usr/bin/env bash

yellow="\e[1;33m"
boldgreen="\033[1;32m"
nocolor="\033[0m"

echo -e "${yellow}Installing the required packages...${nocolor}"
pip3 install -r requirements.txt

echo -e "${yellow}Making LFITester.py executable...${nocolor}"
chmod +x LFITester.py

echo -e "${yellow}Creating symlink for LFITester.py...${nocolor}"
ln -s $(pwd)/LFITester.py /bin/lfitester

echo -e "${boldgreen}Everything\'s setup! Simply run lfitester to get started!${nocolor}"
