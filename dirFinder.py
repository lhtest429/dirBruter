#!/usr/bin/env python
# -*- coding:utf-8 -*-

#from flask import Flask, request, json, Response, jsonify
from multiprocessing import Pool
import json
import threading
import requests
import urllib2
import sys
import threading
from time import ctime,sleep
import threadpool
import nmap
import time

#app = Flask(__name__)

#@app.route('/', methods = ['GET','POST'])


def scan(host):
    resultlist = []
    nm = nmap.PortScanner()
    result = nm.scan(hosts=host, arguments='-p 80,8080,443 --open')
    if len(result["scan"])>0:
        ips =  result["scan"].keys()
        for ip in ips:
            tmp_list = []
            portlist =  result["scan"][ip]["tcp"].keys()
            for port in portlist:
                resultlist.append(host+":"+str(port))
    return resultlist
def main():
    f1 = open('brute.txt','r')
    for u in f1:
        u = u.rstrip()
        tmp = scan(u)
        if tmp != None:
            print u
            check(tmp)
def check(f):
    #if request.method == 'GET':
        #geturl = request.args.get('geturl')
    global g_list
    g_list = []
    urllist = []
    list1 = []
    for u in f:
        u = u.rstrip()
        #dir = ['/admin','/t/344205']
        dir = open("smallrule.txt")
        dirline = dir.readlines()
        for d in dirline:
            d = d.rstrip()
            scheme = ['http://','https://']
            testurl = 'http://'+u+'/happytoseeyou13122213.html'
            try:
                requests.packages.urllib3.disable_warnings()
                resp = requests.get(testurl,allow_redirects=False,timeout=3,verify=False)
                num = len(resp.content)
            except Exception as e:
                num = 0
            for s in scheme:
                #print type(s)
                #print type(geturl)
                #print type(d)
                url = s + u + d
                list1.append(url)
                #print url
        thread_requestor(list1,num)
        #return json.dumps(g_list)


#def res_printer(res1,res2):
#    if res2:
#        g_list.append(res2)
#    else:
#        pass

def thread_requestor(urllist,num):
    pool = Pool(processes=200)
    for url in urllist:
#        print url
        pool.apply_async(getScan, args=(url,num,)) 
    pool.close()
    pool.join()
    #reqs =  threadpool.makeRequests(getScan,urllist,res_printer)


def getScan(url,num):
    try:
        requests.packages.urllib3.disable_warnings()
        resp = requests.get(url, allow_redirects=False, timeout=3,verify=False)
        status = resp.status_code
        content = resp.content
        print "scanning " + url
        #print status
        #print url
        if status == 200 and content.find('No such Host'<=-1) and content.find('ok')<=-1 and len(content)>20 and len(content) != num:
            f = open('vulurl.txt','a')
            f.write(url.strip()+":"+str(len(content))+'\n')
            f.close()
        else:
            pass
    except Exception as e:
        #raise e
        pass

def Filter():
    lines = open('vulurl.txt','r').readlines()
    mydict = {}
    resultlist = []
    for line in lines:
        tmp = line.strip().split(':')
        domain = str(tmp[1].replace('//',''))
        count = int(tmp[3])
        tmpdict = {}
        if domain in mydict.keys():
            if str(count) in mydict[domain].keys():
                mydict[domain][str(count)] = mydict[domain][str(count)]+1
            else:
                mydict[domain][str(count)] = 1
        else:
            mydict[domain] = {}
            mydict[domain][str(count)] = 1
    for k,v in mydict.items():
    #    print k+":"+str(v)
        tmpsum = 0.0
        avg = 0.0
        sqau = 0.0
        maxv = 0.0
        for k1,v1 in v.items():
            if int(v1)<3:
                tmp = k+"&&&"+k1+"&&&"+str(v1)
                #print tmp
                resultlist.append(tmp)  

    for k in resultlist:
        for v in lines:
            #print v.split(":")[3]
            #print k.split('&&&')[1]
            f = open('vulurl_Final.txt','w')
            if v.find(k.split('&&&')[0])>-1 and int(v.split(":")[3]) != 2747 and int(v.split(":")[3]) == int(k.split('&&&')[1]):
                print v
                f.write(v.strip()+'\n')
                #pass
            f.close()
if __name__ == "__main__":
    main()
    Filter()
