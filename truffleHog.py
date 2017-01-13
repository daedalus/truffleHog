#!/usr/bin/env python
import shutil
import sys
import math
import datetime
import argparse
import tempfile
import os
import stat
from git import Repo

if sys.version_info[0] == 2:
    reload(sys)  
    sys.setdefaultencoding('utf8')

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in (ord(c) for c in iterator):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def find_strings(filename):
	fp = open(filename,'r')

	for line in fp:
		printableDiff = line
		foundSomething = False
		
        	for word in line.split():
                	base64_strings = get_strings_of_set(word, BASE64_CHARS)
                        hex_strings = get_strings_of_set(word, HEX_CHARS)
                        for string in base64_strings:
                        	b64Entropy = shannon_entropy(string, BASE64_CHARS)
                                if b64Entropy > 4.5:
                                    foundSomething = True
                                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
                        for string in hex_strings:
                        	hexEntropy = shannon_entropy(string, HEX_CHARS)
                                if hexEntropy > 3:
                                    foundSomething = True
                                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
		if foundSomething:
        		print(printableDiff)
                    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of a file')
    parser.add_argument('filename', type=str, help='filename')


    args = parser.parse_args()
    project_path = find_strings(args.filename)
    #shutil.rmtree(project_path, onerror=del_rw)

