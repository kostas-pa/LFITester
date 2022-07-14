#!/usr/bin/env python3

# CAUTION this script doesn't check for Remote File Inclusion (RFI)

# DISCLAIMER
# ONLY test this on a server you have permission to do it!!!!!!!

from ArgumentHandler import ArgumentHandler
from termcolor import colored
import PayloadManager
import sys
from pyfiglet import Figlet
from proxies_list import clean_proxies
from Crawler import webcrawler
import os
import threading
	
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
		if arghandler.enable_proxies:
			print(colored("Detected Enabled Proxies. Setting up proxy list...",'green'))
			proxyThread = threading.Thread(target=clean_proxies, args=[])
			proxyThread.start()
			proxyThread.join()
		print(colored("This script doesn't check for Remote File Inclusion (RFI)", 'blue'))
		print(colored("If it doesn't show any results that means it didn't find anything!!!", 'blue'))
		if type(arghandler.url) is not list:
			if arghandler.crawler:
				test_urls = webcrawler(arghandler.url, check, arghandler.creds)
				for url in test_urls:
					print(colored(f"Testing: {url}\n\n", 'green'))
					PayloadManager.Payload(url, arghandler.outfile, arghandler.creds, verbosity=arghandler.verbosity, attempt_shell=arghandler.autopwn, mode=arghandler.mode, force=arghandler.force, batch=arghandler.batch, stealth=arghandler.stealth)
			else:
				print(colored(f"Testing: {arghandler.url}\n\n", 'green'))
				PayloadManager.Payload(arghandler.url, arghandler.outfile, arghandler.creds, verbosity=arghandler.verbosity, attempt_shell=arghandler.autopwn, mode=arghandler.mode, force=arghandler.force, batch=arghandler.batch, stealth=arghandler.stealth)
		else:
			if arghandler.crawler:
				for url in arghandler.url:
					test_urls = webcrawler(url, check, arghandler.creds)
					for endpoint in test_urls:
						print(colored(f"Testing: {endpoint}\n\n", 'green'))
						PayloadManager.Payload(endpoint, arghandler.outfile, arghandler.creds, verbosity = arghandler.verbosity, attempt_shell=arghandler.autopwn, mode=arghandler.mode, force=arghandler.force, batch=arghandler.batch, stealth=arghandler.stealth)
			else:
				for url in arghandler.url:
					print(colored(f"Testing: {url}\n\n", 'green'))
					PayloadManager.Payload(url, arghandler.outfile, arghandler.creds, verbosity = arghandler.verbosity, attempt_shell=arghandler.autopwn, mode=arghandler.mode, force=arghandler.force, batch=arghandler.batch, stealth=arghandler.stealth)
	except KeyboardInterrupt:
		print('\nGracefully Exiting...\n')
		os._exit(0)

	
	
if __name__ == '__main__':
	main()

