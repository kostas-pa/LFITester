import argparse
from bannermagic import printBannerPadding, printMessage
from argparse import RawDescriptionHelpFormatter

class ArgumentHandler:

    def __init__(self):
        self.printBanner()
        self.parser = self.ConfigureParser()
        args = self.parser.parse_args()
        self.verbosity = args.verbose
        if args.input_url:
            self.url = args.input_url
        else: 
            if args.input_url_file:
                lines = []
                for line in args.input_url_file:
                    lines.append(line.strip())
                self.url = lines
            else:
                self.url = None
       
        self.crawler = args.crawler
        self.enable_proxies = args.enabled_proxies
        self.outfile = args.outfile
        self.creds = args.creds
        self.autopwn = args.autopwn

    def printBanner(self):
        printBannerPadding('*')
        printMessage('LFITester')
        printMessage('Automated LFI Testing')
        printBannerPadding('*')

    def ConfigureParser(self):   
        parser = argparse.ArgumentParser(prog='LFITester.py', epilog='''Proxies in the list must be in the following format: protocol://{proxyip} 
username:password (newline). If you dont have a authenticated 
proxy then skip the username:password entry and go for a new line

Examples: 
            LFITester.py -u "http://URL?smt=" = test one specific endpoint
            LFITester.py -L test.txt = test a list of endpoints from file
            LFITester.py -c -u "http://URL" = crawl and test all endpoints of that URL
            LFITester.py -c -L test.txt = crawl and test all endpoints for every URL in the file
            LFITester.py --creds abc:abc -u "http://URL?smt=" = test one specific endpoint which requires a login''', formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument('-u', '--url', dest="input_url", metavar='URL', help='The url to test. The URL usually is http://[URL]?[something]=')
        parser.add_argument('-L', '--list-url', dest="input_url_file", metavar='URL_File', help='Input a list of URLs from an external file. The URLs format usually is http://[URL]?[something]=', type=argparse.FileType('r'))
        parser.add_argument('-c', '--crawl', dest="crawler", action='store_true', help='use the crawler to test all the endpoints')
        parser.add_argument('-v', '--verbose', action='count', help='Increase output verbosity', default=0)
        parser.add_argument('-o', '--output', nargs='?', dest="outfile", help='The file to save the results', type=argparse.FileType('w'))
        parser.add_argument('--creds', nargs='?', dest="creds", metavar='user:pass', help='The credentials to login', type=str)
        parser.add_argument('-p', '--enable-proxies', dest="enabled_proxies", action='store_true', help="""Enable proxy redirection. Default proxies are free and you can change them. If you don't want the default proxies you can supply your own and this option will be overridden! Note that the proxies will be picked at random for each request""")
        parser.add_argument('--autopwn', dest='autopwn', metavar='IP', help="If the webapp is vulnerable to LFI then it will attempt to exploit it and give back a shell. This option requires your IP in order to connect with the revshell")
        return parser
