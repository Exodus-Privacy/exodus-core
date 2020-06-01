# Partial code from https://github.com/cpu/AndroidObservatory

import hashlib
import os


def findAPKFiles(dirPath):
    return findFiles(dirPath, ('.APK', '.apk'))


def findCertFiles(dirPath):
    return findFiles(dirPath, ('.RSA', '.DSA'))


def findFiles(dirPath, extensions):
    matches = []
    for root, dirnames, filenames in os.walk(dirPath):
        for filename in filenames:
            if filename.endswith(extensions):
                matches.append(os.path.join(root, filename))
    return matches


def hash(f):
    return hashlib.sha1(f).hexdigest().upper()


def hexToBits(hexString):
    return len(bin(int(hexString, 16))[2:])


def stringToHex(hexString):
    return "".join([line.strip().replace(':', '') for line in hexString])
