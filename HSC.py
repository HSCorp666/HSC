import socket
import requests
import time
import os
from termcolor import *
import instaloader
from scapy.all import *


def prLightGray(skk): print("\033[97m {}\033[00m" .format(skk))


print("\nHSCorp Tool.")
time.sleep(2)
print("||MAKE SURE TO RUN AS ROOT||")
time.sleep(2)

def follow():
    print("OUT OF SERVICE")
    main()

def sniff_sum():
    print("\nSniffing..")
    time.sleep(2)

    sniff(count=300, prn=lambda x: x.summary())
    main()

def sniffy():
    iface = input("\nEnter your interface:-> ")
    print('\n')
    print("\nSniffing..")
    time.sleep(1)
    
    try:
        sniff(iface=iface, prn=lambda sniff: sniff.show())
    except KeyboardInterrupt:
        print("\nExiting..")
        time.sleep(1)
        exit(

        )
def IGSnatch():
    snatcher = instaloader.Instaloader()
    username = input("\nEnter Instagram username:-> ")
    
    print("Snatching..")
    snatcher.download_profile(username, profile_pic_only=True)
    print("\nCheck your folder!")
 
    main()


def webcheck():
    URL = input("\nEnter URL:-> ")
    ip = socket.gethostbyname(URL)
    print("Checking hosts status..")
    reply = os.system('ping -w 5 {} >pingcache.txt'.format(ip))
    if reply == 0:
        prLightGray("\nThe host is up.")
        exit()
    else:
        cprint("\nThe host is down", 'red', attrs='blink')
        exit()


def flooder():
    ip = input("\nEnter IP address:-> ")
    print("\nChecking hosts status.")
    os.system('ping -f {} >pingcache.txt'.format(ip))


def url2ip():
    url = input("\nEnter URL:-> ")
    
    try:
        ip = socket.gethostbyname(url)
        print("\nThe IP adress is", ip)
    except:
        print("Sorry, I could not find the host. :(")
        time.sleep(1)

    main()


def hiddenpages():
    URL = input("\nEnter URL:-> ")
    URLlist = input("Enter filepath for URLlist:-> ")
    ask_src = input("Do you want source code to be enabled? (y/n):-> ")
    if ask_src == 'y':
        src = True
    else:
        src = False

        for line in open('{}'.format(URLlist)):
            ulist = line.strip()
            full_url = URL + '/' + ulist
            responce = requests.get(full_url)
            print('~~~~~~~~~~', responce.url, '~~~~~~~~~~')

            if responce:
                if src == True:
                    print(responce.text)
                print("\nURL FOUND:", responce.url)

                pause = input("\nPress enter to contiune crawling, otherwise type exit:-> ")
                if pause == 'exit':
                    exit()


def main():
    cmd = input("\nEnter a command:-> ")
    if cmd == 'help':
        print(''' 
        1. hidden_pages (Lets you find hidden pages on websites) 
        2. url2ip (Takes a URL and converts it to an IP address.)
        3. bad_flooder (Takes you to a bad flooder.) 
        4. webcheck (Lets you check status of a website.) 
        5. IG_pfp_snatch (Lets you snatch Instagram profile pictures.) 
        6. followbot (Gets you followers.)
        7. net_sniff (Sniffs networks.)
        8. sniff2 (Better network sniffer.)  
        9. sniff_summary (Scans network, but gives you the summary.) \n''')

        main()

    elif cmd == 'hidden_pages':
        hiddenpages()    
    elif cmd == 'url2ip':
        url2ip()
    elif cmd == 'exit':
        exit()
    elif cmd == 'bad_flooder':
        flooder()
    elif cmd == 'webcheck':
        webcheck()
    elif cmd == 'IG_pfp_snatch':
        IGSnatch()
    elif cmd == 'followbot':
        follow()
    elif cmd == 'net_sniff':
        print("\nSniffing.. please press CTRL + C to exit.")
        time.sleep(2)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

            while True:
                print(sock.recvfrom(80))

        except KeyboardInterrupt:
            print("\nExiting, please wait..")
            time.sleep(2)
            exit()

    elif cmd == 'sniff2':
        sniffy()
    
    elif cmd == 'sniff_summary':
        sniff_sum()
    else:
        print("Sorry, I do not understand.")
        time.sleep(1)

        main()

    
main()
