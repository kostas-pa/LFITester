import requests
import lxml
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


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
		if domain in href:
			links.add(href)
	return links




def webcrawler(url):
	endpoints = set()
	linkss = get_links(url)
	for link in linkss:
		if "?" and "=" in link:
			link = link.split("=",1)
			endpoints.add(link[0] + "=")
	return endpoints
