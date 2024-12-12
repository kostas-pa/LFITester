[![Python 3](https://img.shields.io/badge/Python-3-blue.svg)](https://www.python.org/downloads/)
[![GNU V3 License](https://img.shields.io/badge/License-GNUV3-red.svg)](LICENSE)

# DISCLAIMER
• This tool is for educational purposes only.

• We are not responsible for any illegal usage of this tool.



# LFITester

LFITester is a Python3 tool which tests if a server is vulnerable to Local File Inclusion (LFI) attacks.

It runs in Linux/Unix systems but it can run on windows as well. In order to use this program:

• You have to have Python3 installed in your system or you can download it from https://www.python.org/downloads/

• You will also need pip which if you don't have just run ```sudo apt install python3-pip``` for linux.

• Download the program or clone the repository in your system `git clone https://github.com/kostas-pa/LFITester.git`

• Go to the LFITester folder

• First run the command ```sudo chmod +x setup.sh```

• Then run ```sudo ./setup.sh``` which will automatically install the required packages  

• After that you can simply run lfitester as a command.

• It is recommended to run the **--update** flag before initiating an attack

# Supported Attacks

- Path Traversal and bypasses (Null byte, encoding, Filter Bypasses)
- PHP Filter
- Remote Code Execution (RCE) through:
   - Log Poisoning (Apache, Nginx)
   - PHP Session Files
   - PHP Wrappers

```
$python3 LFITester.py 
└──╼ $./LFITester.py 
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
                    [-m Payload] [-f] [--update] [--batch-ans BATCH] [-s] [--poc-file POC] [-H HEADERS] [-C COOKIES]

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
        47: Ncat UDP 

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     The url to test. The URL usually is http://[URL]?[something]=
  -L URL_File, --list-url URL_File
                        Input a list of URLs from an external file. The URLs format usually is http://[URL]?[something]=
  -c, --crawl           use the crawler to test all the endpoints
  -v, --verbose         Increase output verbosity
  -o [OUTFILE], --output [OUTFILE]
                        The file to save the results
  --creds [user:pass]   The credentials to login
  -p, --enable-proxies  Enable proxy redirection. Default proxies are free and you can change them. If you don't want the
                        default proxies you can supply your own and this option will be overridden! Note that the proxies
                        will be picked at random for each request
  --autopwn IP          If the webapp is vulnerable to LFI then it will attempt to exploit it and give back a shell. This
                        option requires your IP in order to connect with the revshell
  -m Payload, --mode Payload
                        Select the payload that suits best. Try different ones if the exploit doesn't work.
  -f, --force           Treat endpoint as alive even if it returns 404
  --update              Update LFITester
  --batch-ans BATCH     Answer all yes/no
  -s, --stealth         Enable stealth mode
  --poc-file POC        Your custom poc file.
  -H HEADERS, --headers HEADERS
                        Add extra headers
  -C COOKIES, --cookies COOKIES
                        Add extra cookies

Proxies in the list must be in the following format: protocol://{proxyip} 
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


```

• Basic Usage: `python3 LFITester.py -u "http://myvulnerabledomain/vulnerable/application?test_param="`

# New Feature AUTOPWN & Threading support
- Automatically opens a reverse shell if it finds RCE (see all the reverse shells in the description).
- Added threads to the attacks and to the proxies which speeds things up significantly!

# ⚠️ Common Issues
• If you are having issues with a URL that has 2 query parameters like http://url?param1=1&param2=2, try to run it with "" like so "http://url?param1=1&param2=2"

• If you are user and you get an error about Git, then try to run lfitester with the sudo command like so **sudo lfitester [flags]**

• If you are having issues with a library, try running the **--update** flag and then ```sudo pip3 install -r requirements.txt``` as the requirements may have changed

• If you can't see the color in the output file but instead you see color codes, google ```[your text editor] display ANSI color codes```.

• If the setup.sh can't install a python package, try installing it manually with the command ```sudo pip3 install [package]```

# Sidenote
• If you like this project please consider giving it a star

# Credits
• To all the contributors for assisting me with this project and for the knowledge they provided.
