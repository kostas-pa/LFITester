import base64
import xml.etree.ElementTree as ET
from termcolor import colored
from urllib.parse import urljoin

class PacketParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.headers = {}
        self.cookies = {}
        self.body = ""
        self.url = ""
        self.host = ""
        self.protocol = "http"
        
    def parse(self):
        """Determine file type and parse accordingly"""
        try:
            with open(self.file_path, 'r') as f:
                content = f.read()
                
            if content.startswith('<?xml'):
                print(colored("[*] Detected Burp Suite XML format", 'blue'))
                return self._parse_burp_file(content)
            else:
                print(colored("[*] Detected raw HTTP format", 'blue'))
                return self._parse_raw_http(content)
        except Exception as e:
            print(colored(f"[!] Error reading packet file: {str(e)}", 'red'))
            raise
    
    def _parse_burp_file(self, content):
        """Parse Burp XML file format"""
        try:
            root = ET.fromstring(content)
            for item in root.findall('.//item'):
                # Get protocol, host and port
                protocol = item.find('protocol')
                host = item.find('host')
                port = item.find('port')
                
                if protocol is not None:
                    self.protocol = protocol.text.lower()
                if host is not None:
                    self.host = host.text
                
                request = item.find('request')
                if request is not None:
                    request_content = request.text
                    is_base64 = request.get('base64', 'false') == 'true'
                    
                    if is_base64:
                        print(colored("[*] Decoding base64 request content", 'blue'))
                        request_content = base64.b64decode(request_content).decode('utf-8')
                    
                    self._parse_raw_http(request_content)
                    break  # Only parse first request for now
            
            # Construct full URL
            if self.host and self.url:
                base_url = f"{self.protocol}://{self.host}"
                self.url = urljoin(base_url, self.url)
                print(colored(f"[+] Constructed full URL: {self.url}", 'green'))
            
            print(colored("[+] Successfully parsed Burp request", 'green'))
            self._print_parsed_info()
            return self.headers, self.cookies, self.body, self.url
        except Exception as e:
            print(colored(f"[!] Error parsing Burp file: {str(e)}", 'red'))
            raise
    
    def _parse_raw_http(self, content):
        """Parse raw HTTP request format"""
        try:
            lines = content.split('\n')
            
            # Parse request line
            if lines[0].startswith('GET') or lines[0].startswith('POST'):
                request_parts = lines[0].split(' ')
                if len(request_parts) >= 2:
                    self.url = request_parts[1]
                    print(colored(f"[+] Found path: {self.url}", 'green'))
            
            # Parse headers and cookies
            header_section = True
            body_lines = []
            
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    header_section = False
                    continue
                    
                if header_section:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if key.lower() == 'host':
                            self.host = value
                            print(colored(f"[+] Found host: {self.host}", 'green'))
                        elif key.lower() == 'cookie':
                            # Parse cookies
                            cookie_pairs = value.split(';')
                            for pair in cookie_pairs:
                                if '=' in pair:
                                    c_key, c_value = pair.strip().split('=', 1)
                                    self.cookies[c_key] = c_value
                        else:
                            self.headers[key] = value
                else:
                    body_lines.append(line)
            
            # For raw HTTP, construct full URL if we have both host and path
            if self.host and self.url and not self.url.startswith('http'):
                base_url = f"{self.protocol}://{self.host}"
                self.url = urljoin(base_url, self.url)
                print(colored(f"[+] Constructed full URL: {self.url}", 'green'))
            
            self.body = '\n'.join(body_lines)
            print(colored("[+] Successfully parsed HTTP request", 'green'))
            self._print_parsed_info()
            return self.headers, self.cookies, self.body, self.url
        except Exception as e:
            print(colored(f"[!] Error parsing HTTP request: {str(e)}", 'red'))
            raise
            
    def _print_parsed_info(self):
        """Print summary of parsed information"""
        if self.headers:
            print(colored(f"[+] Found {len(self.headers)} headers", 'green'))
        if self.cookies:
            print(colored(f"[+] Found {len(self.cookies)} cookies", 'green'))
        if self.body:
            print(colored("[+] Request body found", 'green')) 