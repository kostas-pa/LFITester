import random
import requests


def clean_proxies():
	proxies = []
	with open('proxies', 'r') as handle:
		contents = handle.read().strip()
		for proxy in contents.split('\n'):
			proxies.append(proxy)
	proxy2 = []
	print(proxies)
	for proxy in proxies:
		try:
			response = requests.get('https://google.com', proxies={'https':'https://'+proxy}, timeout=8, verify=False)
			proxy2.append(proxy)
		except requests.exceptions.ConnectTimeout:
			print(f'[-]\tProxy: {proxy} is taking too long to respond. Removing from the list...')
		except requests.exceptions.ProxyError:
			print(f'[-]\tProxy: {proxy} is dead. Removing from the list...')
	proxies = proxy2
	if len(proxies) == 0:
		print("All proxies are dead or unavailable. We recommend you to renew the proxy list. In order to do that you need to edit the 'proxies' file.")
		print("Execution Halt!")
		exit(1)
	with open('proxies', 'w') as handle:
		for proxy in proxies:
			handle.write(proxy + "\n")

def fetch_proxy():
	proxies = []
	with open('proxies', 'r') as handle:
		contents = handle.read().strip()
		for proxy in contents.split('\n'):
			proxies.append(proxy)
	index = random.randint(0,len(proxies)-1)
	return {'https':'https://' + proxies[index],
			'http':'http://' + proxies[index]}
