import os
import sys

import threading
import socket
import bcrypt
import json

lock = threading.Lock()

count = 0


def add1(num):
    global count
    for i in range(0, num):
        count += 1
    print(f'--thread 1: {count}')


def add2(num):
    global count
    for i in range(0, num):
        count += 1
    print(f'--thread 2: {count}')


def HashTest():
    salt = bcrypt.gensalt()
    passwd = "123456"
    hashed = bcrypt.hashpw(passwd.encode('utf8'), salt)
    print(hashed)
    print(bcrypt.checkpw(passwd.encode('utf8'), hashed))


def DictTest():
    color = {'Red': "#FF0000"}
    try:
        print(color['Green'])
    except KeyError as e:
        print('Invalid color')


if __name__ == '__main__':
    # HashTest()
    # DictTest()
    print(ord(' '))

    string = '123abcABC'

    if not string.isalnum():
        print('Password contains illegal characters')
