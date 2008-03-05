#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4 -*-
#
# Sample Clone of Clamd using pyc extension
#
# Copyright (C) 2008 Gianluigi Tiesi <sherpya@netfarm.it>
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

from asynchat import async_chat
from asyncore import dispatcher, loop
from socket import socket, AF_INET, SOCK_STREAM
from sys import exc_info
from tempfile import mkstemp
from os import unlink, write as os_write, close as os_close
import pyc

class CwdHandler(async_chat):
    def __init__(self, conn, addr, server):
        async_chat.__init__(self, conn)
        self.client_address = addr
        self.connection = conn
        self.server = server
        self.set_terminator ('\n')
        self.found_terminator = self.handle_request_line

    def handle_data(self):
        pass

    def handle_request_line(self):
        pass

    def collect_incoming_data(self, data):
        if data.startswith('SCAN '):
            self.do_SCAN(data.split('SCAN ', 1).pop())
        elif data == 'PING':
            self.do_PING()
        elif data.startswith('CONTSCAN '):
            self.do_CONTSCAN(data.split('CONTSCAN ', 1).pop())
        elif data == 'VERSION':
            self.do_VERSION()
        elif data == 'STREAM':
            self.do_STREAM()
        else:
            print 'Unknown command', data
            self.connection.send('UNKNOWN COMMAND\n')

        self.close()

    def scanfile(self, filename, name=None):
        if name is None: name = filename
        ## FIXME: why unc paths are not working here?
        if filename.startswith('\\\\?\\'):
            filename = filename.split('\\\\?\\', 1).pop()
        try:
            infected, virus = pyc.scanFile(filename)
            if infected:
                self.connection.send('%s: %s FOUND\n' % (name, virus))
                print '%s: %s FOUND' % (name, virus)
            else:
                self.connection.send('%s: OK\n' % (name, virus))
        except:
            t, val, tb = exc_info()
            print '%s: ERROR %s' % (name, val.message)
            self.connection.send('%s: ERROR %s\n' % (name, val.message))

    def do_SCAN(self, filename):
        print 'SCAN %s' % filename
        self.connection.send('ERROR Not implemented')

    def do_PING(self):
        self.connection.send('PONG\n')

    def do_CONTSCAN(self, filename):
        print 'CONTSCAN %s' % filename
        self.scanfile(filename)

    def do_VERSION(self):
        version = pyc.getVersions()[0]
        print 'VERSION', version
        self.connection.send(version + '\n')

    def do_STREAM(self):
        stream = socket(AF_INET, SOCK_STREAM)
        stream.settimeout(300)
        stream.bind(('localhost', 0))
        stream.listen(1)
        self.connection.send('PORT %d\n' % stream.getsockname()[1])
        conn, addr = stream.accept()
        f, filename = mkstemp()
        while 1:
            d = conn.recv(1024)
            if not d: break
            os_write(f, d)
        conn.close()
        os_close(f)

        self.scanfile(filename, 'stream')

        try:
            unlink(filename)
        except:
            print 'Error unlinking tempfile'


class Server(dispatcher):
    def __init__(self, ip, port, handler):
        self.ip = ip
        self.port = port
        self.handler = handler
        dispatcher.__init__(self)
        self.create_socket(AF_INET, SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((ip, port))
        self.listen(5)

    def handle_accept(self):
        conn, addr = self.accept()
        self.handler(conn, addr, self)

if __name__ == '__main__':
    port = 3310
    print 'Preloading Virus Database'
    pyc.loadDB()
    s = Server('localhost', port, CwdHandler)
    print "Cwd Server running on port %s" % port
    try:
        loop(timeout=2)
    except KeyboardInterrupt:
        print "Crtl+C pressed. Shutting down."
