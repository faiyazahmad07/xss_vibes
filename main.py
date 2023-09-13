import requests
from Header import Parser
import re
from colorama import Fore
import json
from optparse import OptionParser
import subprocess
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

print(Fore.LIGHTBLUE_EX + """
                 _     _ _______ _______ _    _ _____ ______  _______ _______
                  \___/  |______ |______  \  /    |   |_____] |______ |______
                 _/   \_ ______| ______|   \/   __|__ |_____] |______ ______|
                                #Harmonizing Web Safety
                                #Author: Faiyaz Ahmad
            """ + Fore.WHITE)


parser = OptionParser()
parser.add_option('-f',dest='filename',help="specify Filename to scan. Eg: urls.txt etc")
parser.add_option("-u",dest="url",help="scan a single URL. Eg: http://example.com/?id=2")
parser.add_option('-o',dest='output',help="filename to store output. Eg: result.txt")
parser.add_option('-t',dest='threads',help="no of threads to send concurrent requests(Max: 10)")
parser.add_option('-H',dest='headers',help="specify Custom Headers")
val,args = parser.parse_args()
filename = val.filename
threads = val.threads
output = val.output
url = val.url
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
        #print(final_parameters)
        final_parameters[param_name] = value
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
                    response = requests.get(new_url,params=final_parameters,headers=self.headers).text
                else:
                    response = requests.get(new_url,params=final_parameters).text
                if data + "randomstring" in response:
                    if not threads or threads == 1:
                        print(Fore.GREEN + f"[+] {data} is reflecting in the response")
                    dic[param_name].append(data)
        except Exception as e:
            print(e)

        return dic

    def fuzzer(self, url):
        data = []
        dangerous_characters = [ # You can add dangerous characters here
            ">",
            "'",
            '"',
            "<",
            "/",
            ";"
        ]
        parameters = self.parameters(url)
        if '' in parameters and len(parameters) == 1:
            print(f"[+] NO GET PARAMETER IDENTIFIED...EXITING")
            exit()
        if not threads or int(threads) == 1:
            print(f"[+] {len(parameters)} parameters identified")
        for parameter in parameters:
            if not threads or threads == 1:
                print(f"[+] Testing parameter name: {parameter}")
            out = self.validator(dangerous_characters,parameter,url)
            data.append(out)
        if not threads or threads == 1:
            print("[+] FUZZING HAS BEEN COMPLETED")
        return self.bubble_sort(data)

    def filter_payload(self,arr):
        payload_list = []
        size = int(len(arr) / 2)
        if not threads or threads == 1:
            print(Fore.WHITE + f"[+] LOADING PAYLOAD FILE payloads.json")
        dbs = open("payloads.json")
        dbs = json.load(dbs)
        for char in arr:
            for payload in dbs:
                attributes = payload['Attribute']
                if char in attributes:
                    payload['count'] += 1

        def fun(e):
            return e['count']
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
        out = self.fuzzer(url)
       # print(out)
        for data in out:
            for key in data:
                payload_list = self.filter_payload(data[key])
                #print(f"[+] TESTING THE BELOW PAYLOADS {payload_list}")
            for payload in payload_list:
                try:
                    data = self.parser(url,key,payload)
                    parsed_data = urlparse(url)
                    new_url = parsed_data.scheme +  "://" + parsed_data.netloc + "/" + parsed_data.path
                    #print(new_url)
                    if self.headers:
                        #print("I am here")
                        response = requests.get(new_url,params=data, headers=self.headers).text
                    else:
                        response = requests.get(new_url, params=data).text
                    if payload in response:
                        print(Fore.RED + f"[+] VULNERABLE: {url}\nPARAMETER: {key}\nPAYLAOD USED: {payload}")

                        self.result.append(self.replace(url,key,payload))
                        return True
                except Exception as e:
                    print(e)
        if not threads or threads == 1:
            print(Fore.LIGHTWHITE_EX + f"[+] TARGET SEEMS TO BE NOT VULNERABLE")
        return None

if __name__ == "__main__":
    try:
        #out = []
        #print(headers)
        if url:
            Scanner = Main(url,output,headers=headers)
            Scanner.scanner(url)
            if Scanner.result:
                Scanner.write(output,Scanner.result[0])
            exit()
        Scanner = Main(filename,output,headers=headers)
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
