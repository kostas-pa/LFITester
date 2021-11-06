#!/usr/bin/env python3

# CAUTION this script doesn't check for Remote File Inclusion (RFI)

# DISCLAIMER
# ONLY test this in a server you have permission to do it!!!!!!!

from ArgumentHandler import ArgumentHandler
from termcolor import colored
import PayloadManager
import sys
import git
import os
from pyfiglet import Figlet
from proxies_list import clean_proxies
from Crawler import webcrawler
import pathlib
	
def main():
	try:
		ascii_art = Figlet(font='big')
		print(colored(ascii_art.renderText('LFITester'), 'yellow'))
		arghandler = ArgumentHandler()
		if not arghandler.url:
			arghandler.parser.print_help(sys.stderr)
			exit(1)
		if arghandler.creds is not None:
			check = True
		else:
			check = False
		updatee()
		if arghandler.enable_proxies:
			print(colored("Detected Enabled Proxies. Setting up proxy list...",'green'))
			clean_proxies()
		print(colored("This script doesn't check for Remote File Inclusion (RFI)", 'blue'))
		print(colored("If it doesn't show any results that means it didn't find anything!!!", 'blue'))
		if type(arghandler.url) is not list:
			if arghandler.crawler:
				test_urls = webcrawler(arghandler.url, check, arghandler.creds)
				for url in test_urls:
					print(colored(f"Testing: {url}\n\n", 'green'))
					PayloadManager.Payload(url, arghandler.outfile, arghandler.creds, verbosity=arghandler.verbosity)
			else:
				print(colored(f"Testing: {arghandler.url}\n\n", 'green'))
				PayloadManager.Payload(arghandler.url, arghandler.outfile, arghandler.creds, verbosity=arghandler.verbosity)
		else:
			if arghandler.crawler:
				for url in arghandler.url:
					test_urls = webcrawler(url, check, arghandler.creds)
					for endpoint in test_urls:
						print(colored(f"Testing: {endpoint}\n\n", 'green'))
						PayloadManager.Payload(endpoint, arghandler.outfile, arghandler.creds, verbosity = arghandler.verbosity)
			else:
				for url in arghandler.url:
					print(colored(f"Testing: {url}\n\n", 'green'))
					PayloadManager.Payload(url, arghandler.outfile, arghandler.creds, verbosity = arghandler.verbosity)
	except KeyboardInterrupt:
		print('\nGracefully Exiting...\n')




def updatee():
	print(colored('[!]', 'yellow', attrs=['bold']) + ' Checking for updates...')
	# Get current path of the directory
	cwd = pathlib.Path().resolve()
	# Find the repo of the program
	repo = git.Repo(cwd)
	# Stash any changes done locally so as to not have any problem the pull request
	repo.git.stash()
	# Git pull to do the update
	repo.remotes.origin.pull()
	# Give execute permition to the main program after the update
	cmd = '/usr/bin/chmod +x ' + str(cwd) + '/LFITester.py'
	# execute the command
	os.system(cmd)
	print(colored('[+]', 'green', attrs=['bold']) + ' Updated successfully')	
	
	
if __name__ == '__main__':
	main()

