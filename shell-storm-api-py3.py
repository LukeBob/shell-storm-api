#!/usr/bin/env python3
## https://github.com/MasterMind555/shell-storm-api
## Python3 version of API 
## -*- coding: utf-8 -*-

import sys
import requests

class ShellStorm():
    def __init__(self):
        pass

    def searchShellcode(self, keyword):
        try:
            print("Connecting to shell-storm.org...")
            search = "/api/?s={0}".format(keyword)
            r=requests.get("http://shell-storm.org{0}".format(search))
            data_l = r.text.split('\n')
        except:
            print("Cannot connect to shell-storm.org")
            return(None)

        data_dl = []
        for data in data_l:
            try:
                desc = data.split("::::")
                try:
                    dico = {
                             'ScAuthor': desc[0],
                             'ScArch': desc[1],
                             'ScTitle': desc[2],
                             'ScId': desc[3],
                             'ScUrl': desc[4],
                             'ScSize': int(''.join(x for x in desc[2][-10:-5] if x.isdigit()))
                           }
                except Exception:
                    dico = {
                             'ScAuthor': desc[0],
                             'ScArch': desc[1],
                             'ScTitle': desc[2],
                             'ScId': desc[3],
                             'ScUrl': desc[4],
                             'ScSize': 0
                           }

                data_dl.append(dico)
            except:
                pass

        try:
            return(sorted(data_dl, key=lambda x: x['ScSize'], reverse=True))
        except:
            print('Could not sort by size')

        return(data_dl)

    def displayShellcode(self, shellcodeId):
        if shellcodeId is None:
            return(None)

        try:
            print("Connecting ro shell-storm.org...")
            r=requests.get("http://shell-storm.org")
        except:
            print("Cannot connect to shell-storm.org")
            return(None)

        try:
            url_d = "/shellcode/files/shellcode-"+str(shellcodeId)+".php"
            r=requests.get("http://shell-storm.org{0}".format(url_d))
            data = r.text.split("<pre>")[1].split("<body>")[0]
        except:
            print("Failed to download shellcode from shell-storm.org")
            return(None)

        data = data.replace("&quot;", "\"")
        data = data.replace("&amp;", "&")
        data = data.replace("&lt;", "<")
        data = data.replace("&gt;", ">")

        return(data)

    @staticmethod
    def version():
        print("\nshell-storm API - v0.2")
        print("Search and display all shellcodes in shell-storm database")
        print("Jonathan Salwan - @JonathanSalwan - 2017")
        print("http://shell-storm.org")
        return

class Color():
    @staticmethod
    def red(str):
        return("\033[91m" + str + "\033[0m")

    @staticmethod
    def green(str):
        return("\033[92m" + str + "\033[0m")

    @staticmethod
    def yellow(str):
        return("\033[93m" + str + "\033[0m")

    @staticmethod
    def blue(str):
        return("\033[94m" + str + "\033[0m")


def syntax():
    print("""
Syntax:   {0} <option> <arg>
Options:  -search <keyword>
          -display <shellcode id>
          -version
    """.format(sys.argv[0]))
    sys.exit(-1)

if __name__ == "__main__":

    if len(sys.argv) < 2:
        syntax()

    mod = sys.argv[1]
    if mod != "-search" and mod != "-display" and mod != "-version":
        syntax()

    if mod == "-search":
        if len(sys.argv) < 3:
            syntax()

        api = ShellStorm()
        res_dl = api.searchShellcode(sys.argv[2])
        if not res_dl:
            print("Shellcode not found")
            sys.exit(0)

        print("Found %d shellcodes" % len(res_dl))
        print("%s\t%s" %(Color.blue("ScId"), Color.blue("Title")))
        for data_d in res_dl:
            print("[%s]\t%s - %s" %(Color.yellow(data_d['ScId']), data_d['ScArch'], data_d['ScTitle']))

    elif mod == "-display":
        if len(sys.argv) < 3:
            syntax()
        res = ShellStorm().displayShellcode(sys.argv[2])
        if not res:
            print("Shellcode id not found")
            sys.exit(0)
        print("{0}".format(Color.blue(res)))

    elif mod == "-version":
        ShellStorm.version()
    sys.exit(0)
