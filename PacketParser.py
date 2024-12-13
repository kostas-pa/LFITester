import xml.etree.ElementTree as ET
import base64
import re

class PacketParser:
    def __init__(self, packet_file):
        self.packet_file = packet_file
        self.headers = {}
        self.cookies = {}
        self.body = ""
        self.method = "" # Not implmented
        self.url = ""
        self.path = ""
        self.protocol = "https"
        self.is_burp = "false"
        
        # Determine file type and parse accordingly
        if self.is_burp_file():
            self.parse_burp_file()
        else:
            self.parse_raw_http()

    def is_burp_file(self):
        """Check if file is a Burp Suite XML export"""
        try:
            with open(self.packet_file, 'r') as f:
                first_line = f.readline().strip()
                return first_line.startswith('<?xml')
        except:
            return False

    def parse_burp_file(self):
        """Parse Burp Suite XML export file"""
        self.is_burp = True
        tree = ET.parse(self.packet_file)
        root = tree.getroot()
        
        # Get the first request item
        item = root.find('item')
        if item is None:
            return
            
        # Get the URL from the Burp file
        url_element = item.find('url')
        if url_element is not None and url_element.text is not None:
            self.url = url_element.text.strip()[9:-3]  # Store the URL without CDATA
        else:
            self.url = ""  # Default to empty if not found
        
        # Get the protocol
        protocol = item.find('protocol')
        if protocol is not None and protocol.text is not None:
            self.protocol = protocol.text.strip()  # Store the protocol (http or https)
        else:
            self.protocol = "http"  # Default to http if not specified
        
        # Get base64 encoded request
        request = item.find('request')
        if request is None or request.text is None:
            return
            
        # Decode base64 request
        raw_request = base64.b64decode(request.text).decode('utf-8')
        
        # Parse the raw request
        self.parse_raw_http_content(raw_request)

    def parse_raw_http(self):
        """Parse raw HTTP request file"""
        with open(self.packet_file, 'r') as f:
            content = f.read()
        self.parse_raw_http_content(content)

    def parse_raw_http_content(self, content):
        """Parse raw HTTP request content"""
        # Split headers and body
        parts = content.split('\n\n', 1)
        headers_section = parts[0]
        self.body = parts[1] if len(parts) > 1 else ""

        # Parse the first line to get method and URL
        lines = headers_section.split('\n')

        request_line = lines[0].strip()  # First line contains method and URL
        if request_line and not self.is_burp:
            self.method, self.path, _ = request_line.split(' ', 2)
            
            # Check for Host header
            host = self.headers.get('Host')
            if not host:
                raise ValueError("Not a valid packet file: Host header is missing.")
            
            # Construct the full URL
            self.url = f"{self.protocol}://{host}{self.path}"  # Update URL construction
            # self.path = self.url.split('?')[0]  # Extract path without query parameters

        # Parse headers
        for line in lines[1:]:  # Skip first line (HTTP method line)
            if not line.strip():
                continue
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                # Handle cookies separately
                if key.lower() == 'cookie':
                    self.parse_cookies(value)
                else:
                    self.headers[key] = value

    def parse_cookies(self, cookie_string):
        """Parse cookie string into dictionary"""
        cookies = cookie_string.split(';')
        for cookie in cookies:
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                self.cookies[key.strip()] = value.strip()

    def get_headers(self):
        """Return parsed headers"""
        return self.headers

    def get_cookies(self):
        """Return parsed cookies"""
        return self.cookies

    def get_body(self):
        """Return request body"""
        return self.body

    def get_method(self):
        """Return HTTP method"""
        return self.method

    def get_url(self):
        """Return full URL"""
        return self.url

    def get_path(self):
        """Return path of the URL without query peramiters"""
        return self.path
