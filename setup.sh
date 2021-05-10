#!/bin/bash

echo Making LFITester.py executable...
chmod +x LFITester.py

echo Creating symlink for LFITester.py
ln -s $(pwd)/LFITester.py /bin/LFITester

echo Everything\'s setup! Simply run LFITester to get started!