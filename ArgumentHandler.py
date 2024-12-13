import argparse
from bannermagic import printBannerPadding, printMessage
from argparse import RawDescriptionHelpFormatter
import pathlib
try:
    import git
except ImportError:
    print("There were issues importing git. Auto-update might fail...")
import os
from termcolor import colored
from PacketParser import PacketParser


class ArgumentHandler:

    def __init__(self):
        self.printBanner()
        self.parser = self.ConfigureParser()
        args = self.parser.parse_args()

        if args.update:
            self.update()
            exit()
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

        self.override_poc = False
        self.poc = None
        if args.poc:
            lines = []
            for line in args.poc:
                lines.append(line.strip())
            self.poc = lines
            self.override_poc = True
       
        self.crawler = args.crawler
        self.enable_proxies = args.enabled_proxies
        self.outfile = args.outfile
        self.creds = args.creds
        self.headers = args.headers
        self.cookies = args.cookies
        self.autopwn = args.autopwn
        self.mode = args.mode
        
        self.force = args.force
        if self.mode == None:
            self.mode = 0

        self.stealth = args.stealth
        if args.batch != None:
            if args.batch.lower() == 'yes':
                self.batch = True
            elif args.batch.lower() == 'no':
                self.batch = False
            else:
                self.batch = None
        else:
            self.batch = None

        # Parse packet file if provided
        if args.packet_file:
            parser = PacketParser(args.packet_file)
            if not self.headers:  # Only use parsed headers if none provided via CLI
                self.headers = parser.get_headers()
            if not self.cookies:  # Only use parsed cookies if none provided via CLI
                self.cookies = parser.get_cookies()


    def update(self):
        print(colored('[!]', 'yellow', attrs=['bold']) + ' Checking for updates...')
        # Get path of the directory of the repo
        repo_path = os.path.dirname(__file__)
        # Find the repo of the program
        repo = git.Repo(repo_path)
        # Stash any changes done locally so as to not have any problem the pull request
        repo.git.stash()
        # Git pull to do the update
        repo.remotes.origin.pull()
        # Give execute permition to the main program after the update
        cmd = '/usr/bin/chmod +x ' + str(repo_path) + '/LFITester.py'
        # execute the command
        os.system(cmd)
        print(colored('[+]', 'green', attrs=['bold']) + ' Updated successfully')

    def printBanner(self):
        printBannerPadding('*')
        printMessage('LFITester')
        printMessage('Automated LFI Testing')
        printBannerPadding('*')

    def ConfigureParser(self):   
        parser = argparse.ArgumentParser(prog='LFITester.py', description="""
        Payload Modes:
        0:  Simple bash TCP
        1:  Alternative bash TCP
        2:  Simple sh UDP
        3:  Alternative sh TCP
        4:  Perl TCP
        5:  Alternative Perl TCP
        6:  Python TCP
        7:  Alternative python TCP
        8:  Alternative 2 python TCP
        9:  Alternative 3 python TCP
        10: Alternative (No Spaces) python TCP
        11: Alternative (No Spaces) 2 python TCP
        12: Alternative (No Spaces) 3 python TCP
        13: Alternative (No Spaces) Shortened python TCP
        14: Alternative (No Spaces) Shortened 2 python TCP
        15: Alternative (No Spaces) Shortened 3 python TCP
        16: Alternative (No Spaces) Shortened Further python TCP
        17: Alternative (No Spaces) Shortened Further 2 python TCP
        18: Alternative (No Spaces) Shortened Further 3 python TCP
        19: Python3 TCP
        20: Alternative python3 TCP
        21: Alternative 2 python3 TCP
        22: Alternative 3 python3 TCP
        23: Alternative (No Spaces) python3 TCP
        24: Alternative (No Spaces) 2 python3 TCP
        25: Alternative (No Spaces) 3 python3 TCP
        26: Alternative (No Spaces) Shortened python3 TCP
        27: Alternative (No Spaces) Shortened 2 python3 TCP
        28: Alternative (No Spaces) Shortened 3 python3 TCP
        29: Alternative (No Spaces) Shortened Further python3 TCP
        30: Alternative (No Spaces) Shortened Further 2 python3 TCP
        31: Alternative (No Spaces) Shortened Further 3 python3 TCP
        32: Php exec
        33: Php shell_exec
        34: Php over sh
        35: Php system
        36: Php passthru
        37: Php popen
        38: Php proc_open
        39: Ruby
        40: Ruby Alternative
        41: Go
        42: Netcat sh
        43: Netcat bash
        44: Netcat alternative bash
        45: Netcat openBSD
        46: Ncat
        47: Ncat UDP """ ,
        epilog='''Proxies in the list must be in the following format: protocol://{proxyip} 
username:password (newline). If you dont have a authenticated 
proxy then skip the username:password entry and go for a new line


Examples: 
            LFITester.py -u "http://URL?smt=" = test one specific endpoint
            LFITester.py -L test.txt = test a list of endpoints from file
            LFITester.py -c -u "http://URL" = crawl and test all endpoints of that URL
            LFITester.py -c -L test.txt = crawl and test all endpoints for every URL in the file
            LFITester.py --creds abc:abc -u "http://URL?smt=" = test one specific endpoint which requires a login

Developers: Konstantinos Papanagnou (https://github.com/Konstantinos-Papanagnou)
            Konstantinos Pantazis   (https://github.com/kostas-pa)
            ''', formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument('-u', '--url', dest="input_url", metavar='URL', help='The url to test. The URL usually is http://[URL]?[something]=')
        parser.add_argument('-L', '--list-url', dest="input_url_file", metavar='URL_File', help='Input a list of URLs from an external file. The URLs format usually is http://[URL]?[something]=', type=argparse.FileType('r'))
        parser.add_argument('-c', '--crawl', dest="crawler", action='store_true', help='use the crawler to test all the endpoints')
        parser.add_argument('-v', '--verbose', action='count', help='Increase output verbosity', default=0)
        parser.add_argument('-o', '--output', nargs='?', dest="outfile", help='The file to save the results', type=argparse.FileType('w'))
        parser.add_argument('--creds', nargs='?', dest="creds", metavar='user:pass', help='The credentials to login', type=str)
        parser.add_argument('-p', '--enable-proxies', dest="enabled_proxies", action='store_true', help="""Enable proxy redirection. Default proxies are free and you can change them. If you don't want the default proxies you can supply your own and this option will be overridden! Note that the proxies will be picked at random for each request""")
        parser.add_argument('--autopwn', dest='autopwn', metavar='IP', help="If the webapp is vulnerable to LFI then it will attempt to exploit it and give back a shell. This option requires your IP in order to connect with the revshell", type=str)
        parser.add_argument('-m', '--mode', dest='mode', metavar='Payload', help='Select the payload that suits best. Try different ones if the exploit doesn\'t work.', type=int)
        parser.add_argument('-f', '--force', dest='force', help="Treat endpoint as alive even if it returns 404", action='store_true')
        parser.add_argument('--update', dest='update', help="Update LFITester", action='store_true')
        parser.add_argument('--batch-ans', dest='batch', help="Answer all yes/no", type=str)
        parser.add_argument('-s', '--stealth', dest='stealth', help='Enable stealth mode', action='store_true')
        parser.add_argument('--poc-file', dest='poc', help="Your custom poc file.", type=argparse.FileType('r'))
        parser.add_argument('-H', '--headers', dest="headers", metavar='HEADERS', help='Add extra headers')
        parser.add_argument('-C', '--cookies', dest="cookies", metavar='COOKIES', help='Add extra cookies')
        parser.add_argument("-r", '--packet-file', dest="packet_file", metavar='PACKET_FILE', 
                           help='Import headers/cookies/body from a packet file (HTTP or Burp format)')
        return parser


