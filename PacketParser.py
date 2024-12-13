import xml.etree.ElementTree as ET
import base64
import re

class PacketParser:
    def __init__(self, packet_file):
        self.packet_file = packet_file
        self.headers = {}
        self.cookies = {}
        self.body = ""
        self.method = "GET"
        self.url = ""
        self.path = ""
        self.protocol = "https"
        self.is_burp = False
        
        # Parse the file
        self._parse_file()

    def _parse_file(self):
        """Determine file type and parse accordingly"""
        with open(self.packet_file, 'r') as f:
            content = f.read()
            
        # Check if it's a Burp file by looking for burpVersion
        if 'burpVersion' in content:
            self.is_burp = True
            self._parse_burp_file()
        else:
            self._parse_raw_file()

    def _parse_burp_file(self):
        """Parse Burp XML file"""
        tree = ET.parse(self.packet_file)
        root = tree.getroot()
        
        # Get the first item element
        item = root.find('item')
        if item is None:
            return
            
        # Get base request
        request_elem = item.find('request')
        if request_elem is None:
            return
            
        # Check if request is base64 encoded
        is_base64 = request_elem.get('base64', 'false') == 'true'
        request_data = request_elem.text
        
        if is_base64:
            request_data = base64.b64decode(request_data).decode('utf-8')
            
        # Parse the raw request data
        self._parse_raw_request(request_data)
        
        # Get URL from Burp file
        url_elem = item.find('url')
        if url_elem is not None:
            self.url = url_elem.text
            
        # Get protocol
        protocol_elem = item.find('protocol') 
        if protocol_elem is not None:
            self.protocol = protocol_elem.text

    def _parse_raw_file(self):
        """Parse raw request file"""
        with open(self.packet_file, 'r') as f:
            raw_request = f.read()
        self._parse_raw_request(raw_request)

    def _parse_raw_request(self, raw_request):
        """Parse raw HTTP request string"""
        # Split into lines
        lines = raw_request.split('\n')
        
        # Parse first line for method and path
        if lines:
            first_line = lines[0].strip()
            parts = first_line.split(' ')
            if len(parts) >= 2:
                self.method = parts[0]
                self.path = parts[1]
        
        # Parse headers and cookies
        header_section = True
        body_lines = []
        
        for line in lines[1:]:
            line = line.strip()
            
            # Empty line marks end of headers
            if not line:
                header_section = False
                continue
                
            if header_section:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Parse cookies
                    if key.lower() == 'cookie':
                        cookies = value.split(';')
                        for cookie in cookies:
                            if '=' in cookie:
                                c_key, c_value = cookie.split('=', 1)
                                self.cookies[c_key.strip()] = c_value.strip()
                    
                    self.headers[key] = value
                    
                    # Check for Host header to construct URL
                    if key.lower() == 'host':
                        self.url = f"https://{value.strip()}{self.path}"
            else:
                body_lines.append(line)
        
        self.body = '\n'.join(body_lines)

    def get_headers(self):
        """Return parsed headers without 'Host' header"""
        headers_copy = self.headers.copy()  # Create a copy of the headers
        # Remove the 'Host' header if it exists, regardless of case
        headers_copy = {k: v for k, v in headers_copy.items() if k.lower() != 'host'}
        
        print("\nHeaders\n", headers_copy)
        return headers_copy

    def get_cookies(self):
        """Return parsed cookies"""
        print("\nCookies\n", self.cookies)
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
        """Return path of the URL"""
        return self.path

    def get_protocol(self):
        """Return protocol (http/https)"""
        return self.protocol

    def is_burp_file(self):
        """Return whether file is a Burp file"""
        return self.is_burp
