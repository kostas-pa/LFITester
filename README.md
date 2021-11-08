[![Python 3](https://img.shields.io/badge/Python-3-blue.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

# DISCLAIMER
• This tool is for educational purpuses only.

• We are not responsible for any illegal usage of this tool.



# LFITester

LFITester is a Python3 tool which tests if a server is vulnerable to Local File Inclusion (LFI) attack.

It runs in Linux/Unix systems but it can run on windows as well. In order to use this program:

• You have to have Python3 installed in your system or you can download it from https://www.python.org/downloads/

• You will also need pip which if you don't have just run ```sudo apt install python3-pip``` for linux.

• Download the program or clone the repository in your system `git clone https://github.com/kostas-pa/LFITester.git`

• Go to the LFITester folder

• First run the command ```chmod +x setup.sh```

• Then run ```pip3 install -r requirements.txt``` and ```sudo ./setup.sh```

• After that you can simply run lfitester as a command.

```
$python3 LFITester.py 
 _      ______ _____ _______        _            
| |    |  ____|_   _|__   __|      | |           
| |    | |__    | |    | | ___  ___| |_ ___ _ __ 
| |    |  __|   | |    | |/ _ \/ __| __/ _ \ '__|
| |____| |     _| |_   | |  __/\__ \ ||  __/ |   
|______|_|    |_____|  |_|\___||___/\__\___|_|   
                                                 
                                                 

**********************************************************************************************************************************************************************************************
                                                                                          LFITester
                                                                                    Automated LFI Testing
**********************************************************************************************************************************************************************************************
usage: LFITester.py [-h] [-u URL] [-L URL_File] [-c] [-v] [-o [OUTFILE]] [--creds [user:pass]] [-p] [--autopwn IP]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     The url to test. The URL usually is http://[URL]?[something]=
  -L URL_File, --list-url URL_File
                        Input a list of URLs from an external file. The URLs format usually is http://[URL]?[something]=
  -c, --crawl           use the crawler to test all the endpoints
  -v, --verbose         Increase output verbosity
  -o [OUTFILE], --output [OUTFILE]
                        The file to save the results
  --creds [user:pass]   The credentials to login
  -p, --enable-proxies  Enable proxy redirection. Default proxies are free and you can change them. If you don't want the default proxies you can supply your own and this option will be
                        overridden! Note that the proxies will be picked at random for each request
  --autopwn IP          If the webapp is vulnerable to LFI then it will attempt to exploit it and give back a shell. This option requires your IP in order to connect with the revshell

Proxies in the list must be in the following format: protocol://{proxyip} 
username:password (newline). If you dont have a authenticated 
proxy then skip the username:password entry and go for a new line

Examples: 
            LFITester.py -u "http://URL?smt=" = test one specific endpoint
            LFITester.py -L test.txt = test a list of endpoints from file
            LFITester.py -c -u "http://URL" = crawl and test all endpoints of that URL
            LFITester.py -c -L test.txt = crawl and test all endpoints for every URL in the file
            LFITester.py --creds abc:abc -u "http://URL?smt=" = test one specific endpoint which requires a login

```

• Basic Usage: `python3 LFITester.py -v -u "http://myvulnerabledomain/vulnerable/application?test_param="`

# New Features AUTOPWN
Coding Autopwn. Can be unstable. This feature is under development and testing.

# Sidenote
• If you like this project please consider giving it a star

# Credits
• To [Konstantinos Pap](https://github.com/Konstantinos-Papanagnou) for assisting me with this project and for the knowledge he provided.
