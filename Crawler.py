import requests
import lxml
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from UAList import fetchUA
from requests.auth import HTTPBasicAuth


def get_links_creds(url,creds_str):
	links = set()
	domain = urlparse(url).netloc
	list_creds = creds_str.split(':')
	user = list_creds[0]
	passwd = list_creds[1]
	soup = BeautifulSoup(requests.get(url, auth=HTTPBasicAuth(user, passwd)).content, "html.parser")
	for a_tag in soup.find_all('a'):
		href = a_tag.get("href")
		if href == "" or href is None:
			continue
		href = urljoin(url, href)
		if domain in href:
			links.add(href)
	return links


def get_links(url):
	# I use set() because sets don't allow duplicates	
	links = set()
	# Get only the domain name to crawl it
	domain = urlparse(url).netloc
	soup = BeautifulSoup(requests.get(url).content, "html.parser")
	for a_tag in soup.find_all('a'):
		href = a_tag.get("href")
		if href == "" or href is None:
			continue
		# Join the URL if it's relative
		href = urljoin(url, href)
		# This if statement ensures that all the URLs tested will be internal
		if domain in href:
			links.add(href)
	# UPGRADE: add searching of "img src=" tags 
	for src_tag in soup.find_all('img'):
		href = src_tag.get("src")
		if href == "" or href is None:
			continue
		# Join the URL if it's relative
		href = urljoin(url, href)
		# This if statement ensures that all the URLs tested will be internal
		if domain in href:
			links.add(href)
	return links




def webcrawler(url, check, creds_str):
	endpoints = set()
	domain = urlparse(url).netloc
	if check:
		linkss = get_links_creds(url, creds_str)
	else:
		linkss = get_links(url)
	# UPGRADE: when in URL exist only "?" (no "=") then do nothing (don't add payloads to that URL after "?")    
	for link in linkss:
		if "?" in link:
			if "=" in link:
				if domain in link:
					link = link.split("=",1)
					endpoints.add(link[0] + "=")
	print(endpoints)
	return endpoints
