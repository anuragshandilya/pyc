#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4 -*-
#
# Client for clamd - old proto (newline)
#
# Copyright (C) 2009 Gianluigi Tiesi <sherpya@netfarm.it>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
# ======================================================================

from socket import socket, AF_INET, SOCK_STREAM
from os import getcwd
from os.path import join as path_join

EICAR='*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X'[::-1]

def connect():
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(('localhost', 3310))
    f = s.makefile('rw', 0)
    return f

if __name__ == '__main__':
    f = connect()
    f.write('SESSION\n')
    filename = path_join(getcwd(), 'clam.exe')
    f.write('SCAN ' + filename + '\n')
    print f.readline().strip()

    f.write('STREAM\n')
    port = int(f.readline().strip().split('PORT ', 1).pop())
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(('localhost', port))
    s.send(EICAR)
    s.close()
    print f.readline().strip()

    f.write('STREAM\n')
    port = int(f.readline().strip().split('PORT ', 1).pop())
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(('localhost', port))
    s.send(open('clam.exe', 'rb').read())
    s.close()
    print f.readline().strip()

    f.write('END\n')
    f.close()
