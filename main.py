import requests
from Header import Parser
import re
from adder import Adder
from colorama import Fore
import json
from Waf import Waf_Detect
from optparse import OptionParser
import subprocess
import sys
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

print(Fore.LIGHTBLUE_EX + """
                 _     _ _______ _______  _    _ _____ ______  _______ _______
                  \___/  |______ |______   \  /    |   |_____] |______ |______
                 _/   \_ ______| ______|    \/   __|__ |_____] |______ ______|
                                 #Harmonizing Web Safety
                                  #Author: Faiyaz Ahmad
            """ + Fore.WHITE)


parser = OptionParser()

parser.add_option('-f', dest='filename', help="specify Filename to scan. Eg: urls.txt etc")
parser.add_option("-u", dest="url", help="scan a single URL. Eg: http://example.com/?id=2")
parser.add_option('-o', dest='output', help="filename to store output. Eg: result.txt")
parser.add_option('-t', dest='threads', help="no of threads to send concurrent requests(Max: 10)")
parser.add_option('-H', dest='headers', help="specify Custom Headers")
parser.add_option('--waf', dest='waf',action='store_true', help="detect web application firewall and then test payloads")
parser.add_option('-w', dest='custom_waf',help='use specific payloads related to W.A.F')
parser.add_option('--crawl',dest='crawl',help='crawl then find xss',action="store_true")
parser.add_option('--pipe',dest="pipe",action="store_true",help="pipe output of a process as an input")

val,args = parser.parse_args()
filename = val.filename
threads = val.threads
output = val.output
url = val.url
crawl = val.crawl
waf = val.waf
pipe = val.pipe
custom_waf = val.custom_waf
headers = val.headers

try:
    if headers:
        print(Fore.WHITE + "[+] HEADERS: {}".format(headers))
        headers = Parser.headerParser(headers.split(','))
except AttributeError:
    headers = Parser.headerParser(headers.split())

try:
    threads = int(threads)
except TypeError:
    threads = 1
if threads > 10:
    threads = 7

if crawl:
    filename = f"{url.split('://')[1]}_katana"

class Main:

    def __init__(self,url=None, filename=None, output=None,headers=None):
        self.filename = filename
        self.url = url
        self.output = output
        self.headers = headers
        #print(headers)
        self.result = []

    def read(self,filename):
        '''
        Read & sort GET  urls from given filename
        '''
        print(Fore.WHITE + "READING URLS")
        urls = subprocess.check_output(f"cat {filename} | grep '=' | sort -u",shell=True).decode('utf-8')
        if not urls:
            print(Fore.GREEN + f"[+] NO URLS WITH GET PARAMETER FOUND")
        return urls.split()

    def write(self, output, value):
        '''
        Writes the output back to the given filename.
        '''
        if not output:
            return None
        subprocess.call(f"echo '{value}' >> {output}",shell=True)

    def replace(self,url,param_name,value):
        return re.sub(f"{param_name}=([^&]+)",f"{param_name}={value}",url)
    def bubble_sort(self, arr):
        '''
        For sorting the payloads
        '''
        #print(arr)
        a = 0
        keys = []
        for i in arr:
            for j in i:
                keys.append(j)
        #print(keys)
        while a < len(keys) - 1:
            b = 0
            while b < len(keys) - 1:
                d1 = arr[b]
                #print(d1)
                d2 = arr[b + 1]
               # print(d2)
                if len(d1[keys[b]]) < len(d2[keys[b+1]]):
                    d = d1
                    arr[b] = arr[b+1]
                    arr[b+1] = d
                    z = keys[b+1]
                    keys[b+1] = keys[b]
                    keys[b] = z
                b += 1
            a += 1
        return arr
    
    def crawl(self):
        '''
        Use this method to crawl the links using katana (return type: None)
        '''
        print(Fore.BLUE + "[+] CRAWLING LINKS")
        subprocess.check_output(f"katana -u {url} -jc -d 4 -o {url.split('://')[1]}_katana",shell=True)
        print(Fore.BLUE + f"[+] RESULT SAVED AS {url.split('://')[1]}_katana")
        return None



    def parameters(self, url):

        '''
        This function will return every parameter in the url as dictionary.
        '''

        param_names = []
        params = urlparse(url).query
        params = params.split("&")
        if len(params) == 1:
            params = params[0].split("=")
            param_names.append(params[0])
            # print("I am here")
        else:
            for param in params:
                param = param.split("=")
                # print(param)
                param_names.append(param[0])
        return param_names

    def parser(self, url, param_name, value):
        '''
        This function will replace the parameter's value with the given value and returns a dictionary
        '''
        final_parameters = {}
        parsed_data = urlparse(url)
        params = parsed_data.query
        protocol = parsed_data.scheme
        hostname = parsed_data.hostname
        path = parsed_data.path
        params = params.split("&")
        if len(params) == 1:
            params = params[0].split("=")
            final_parameters[params[0]] = params[1]
            #print("I am here")
        else:
            for param in params:
                param = param.split("=")
                #print(param)
                final_parameters[param[0]] = param[1]
        #print(final_parameters[param_name] + value)
        final_parameters[param_name] = value
        #print(final_parameters)
        return final_parameters

    def validator(self, arr, param_name, url):
        dic = {param_name: []}
        try:
            for data in arr:
                final_parameters = self.parser(url,param_name,data + "randomstring")
                new_url = urlparse(url).scheme + "://" + urlparse(url).hostname + "/" + urlparse(url).path
                #print(new_url)
                if self.headers:
                    #print("I am here")
                    response = requests.get(new_url,params=final_parameters,headers=self.headers,verify=False).text
                else:
                    response = requests.get(new_url,params=final_parameters,verify=False).text
                if data + "randomstring" in response:
                    if not threads or threads == 1:
                        print(Fore.GREEN + f"[+] {data} is reflecting in the response")
                    dic[param_name].append(data)
        except Exception as e:
            print(e)

        return dic

    def fuzzer(self, url):
        data = []
        dangerous_characters = Adder().dangerous_characters
        parameters = self.parameters(url)
        if '' in parameters and len(parameters) == 1:
            print(f"[+] NO GET PARAMETER IDENTIFIED...EXITING")
            exit()
        if not threads or int(threads) == 1:
            print(f"[+] {len(parameters)} parameters identified")
        for parameter in parameters:
            if not threads or threads == 1:
                print(Fore.WHITE + f"[+] Testing parameter name: {parameter}")
            out = self.validator(dangerous_characters,parameter,url)
            data.append(out)
        if not threads or threads == 1:
            print("[+] FUZZING HAS BEEN COMPLETED")
        return self.bubble_sort(data)

    def filter_payload(self,arr,firewall):
        payload_list = []
        size = int(len(arr) / 2)
        if not threads or threads == 1:
            print(Fore.WHITE + f"[+] LOADING PAYLOAD FILE payloads.json")
        dbs = open("payloads.json")
        dbs = json.load(dbs)
        #print(dbs)
        new_dbs = []
        #print(firewall)
        if firewall:
            print(Fore.GREEN + f"[+] FILTERING PAYLOADS FOR {firewall.upper()}")
            try:
                for i in range(0,len(dbs)):
                    if dbs[i]['waf'] == firewall:
                        #print(1)
                        new_dbs.append(dbs[i])
                    #size = len(dbs)
            except Exception as e:
                print(e)
            if not new_dbs:
                print(Fore.GREEN + "[+] NO PAYLOADS FOUND FOR THIS WAF")
                exit()
        else:
            for i in range(0,len(dbs)):
                if not dbs[i]['waf']:
                    new_dbs.append(dbs[i])
        dbs = new_dbs
        #print(dbs)
        for char in arr:
            for payload in dbs:
                attributes = payload['Attribute']
                if char in attributes:
                    payload['count'] += 1
        #print(dbs)
        def fun(e):
            return e['count']

        #size = int(len(dbs) / 2)
        dbs.sort(key=fun,reverse=True)
        #print(dbs)
        for payload in dbs:
            if payload['count'] == len(arr) and len(payload['Attribute']) == payload['count'] :
                #print(payload)
                if not threads or threads == 1:
                    print(Fore.GREEN + f"[+] FOUND SOME PERFECT PAYLOADS FOR THE TARGET")
                #print(payload['count'],len(payload['Attributes']))
                payload_list.insert(0,payload['Payload'])
                #print(payload_list)
                continue
            if payload['count'] > size:
                payload_list.append(payload['Payload'])
                continue
        return payload_list


    def scanner(self,url):
        print(Fore.WHITE + f"[+] TESTING {url}")
        if waf:
            print(Fore.LIGHTGREEN_EX + "[+] DETECTING WAF")
            firewall = Waf_Detect(url).waf_detect()
            if firewall:
                print(Fore.LIGHTGREEN_EX + f"[+] {firewall.upper()} DETECTED")
            else:
                print(Fore.LIGHTGREEN_EX + f"[+] NO WAF FOUND! GOING WITH THE NORMAL PAYLOADS")
                firewall = None
        elif custom_waf:
            #print(1)
            firewall = custom_waf
        else:
            firewall = None
        out = self.fuzzer(url)
       # print(out)
        for data in out:
            for key in data:
                payload_list = self.filter_payload(data[key],firewall)
                #print(f"[+] TESTING THE BELOW PAYLOADS {payload_list}")
            for payload in payload_list:
                try:
                    #print(f"Testing: {payload}")
                    data = self.parser(url,key,payload)
                    parsed_data = urlparse(url)
                    new_url = parsed_data.scheme +  "://" + parsed_data.netloc + parsed_data.path
                    #print(new_url)
                    #print(data)
                    if self.headers:
                        #print("I am here")
                        response = requests.get(new_url,params=data, headers=self.headers,verify=False).text
                    else:
                        response = requests.get(new_url, params=data,verify=False).text
                    if payload in response:
                        print(Fore.RED + f"[+] VULNERABLE: {url}\nPARAMETER: {key}\nPAYLOAD USED: {payload}")
                        print(self.replace(url,key,payload))
                        self.result.append(self.replace(url,key,payload))
                        return True
                except Exception as e:
                    print(e)
        if not threads or threads == 1:
            print(Fore.LIGHTWHITE_EX + f"[+] TARGET SEEMS TO BE NOT VULNERABLE")
        return None

if __name__ == "__main__":
    urls = []
    Scanner = Main(filename, output, headers=headers)
    try:
        #out = []
        #print(headers)
        if url and not filename:
            Scanner = Main(url,output,headers=headers)
            Scanner.scanner(url)
            if Scanner.result:
                Scanner.write(output,Scanner.result[0])
            exit()
        elif filename and crawl:
            Scanner.crawl()
            urls = Scanner.read(filename)
        elif pipe:
            out = sys.stdin
            for url in out:
                urls.append(url)
        else:
            urls = Scanner.read(filename)
        print(Fore.GREEN + "[+] CURRENT THREADS: {}".format(threads))
        '''
        for url in urls:
            print(Fore.WHITE + f"[+] TESTING {url}")
            vuln = Scanner.scanner(url)
        '''
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(Scanner.scanner,urls)
        for i in Scanner.result:
            Scanner.write(output,i)
        print(Fore.WHITE + "[+] COMPLETED")
    except Exception as e:
        print(e)

#print(Main("test.txt","out.txt").replace("http://testphp.vulnweb.com/listproducts.php?cat=1","cat","superman"))
