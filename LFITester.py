#!/usr/bin/env python3

# CAUTION this script doesn't check for Remote File Inclusion (RFI)

# DISCLAIMER
# ONLY test this in a server you have permission to do it!!!!!!!

from ArgumentHandler import ArgumentHandler
from termcolor import colored
import PayloadManager

	
def main():
	try:
		arghandler = ArgumentHandler()
		print(colored("This script doesn't check for Remote File Inclusion (RFI)", 'blue'))
		print(colored("If it doesn't show any results that means it didn't find anything!!!", 'blue'))
		PayloadManager.Payload(arghandler.url, verbosity=arghandler.verbosity)
	except KeyboardInterrupt:
		print('\nGracefully Exiting...\n')
	
	
	
	
if __name__ == '__main__':
	main()

