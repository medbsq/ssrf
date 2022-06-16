


# ssrf 


                           __  __  byMedbsq              
             ___ ___ _ __ / _|/ _|_   _ ________
            / __/ __| '__| |_| |_| | | |_  /_  /
            \__ \__ \ |  |  _|  _| |_| |/ / / / 
            |___/___/_|  |_| |_|  \__,_/___/___|
             https://github.com/medbsq/ssrf.git
            
server side request forgery (ssrf)  fuzzer,this script will automate the scan for ssrf vulnerabilites   using a deferent techniques . by providing an  burp suite colaborator ,this script will generate a file that contain a unique hash for every scanned URL.


## Usage: 
```
ssrf_header -f <url_fielname> -c  <colaborato> -t <threads_number>
```

## Options:
  ```
  -h, --help   show this help message and exit
  -f URL_FILE  spicify the urls file
  -c COLAB     burp suite colaborator
  -t THREADS   set nubmer of threads
  -o OUTPUT    set output file
```
