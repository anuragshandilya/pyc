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
from select import select
from sys import exc_info
from tempfile import mkstemp
from time import time
from os import unlink, write as os_write, close as os_close
from os.path import isfile, isdir
from sys import stdout
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

    def scanfile(self, filename, name):
        ## FIXME: why unc paths are not working here?
        if filename.startswith('\\\\?\\'):
            filename = filename.split('\\\\?\\', 1).pop()
        try:
            infected, virus = pyc.scanFile(filename)
            if infected:
                self.connection.send('%s: %s FOUND\n' % (name, virus))
                print '%s: %s FOUND' % (name, virus)
            else:
                self.connection.send('%s: OK\n' % name)
        except:
            t, val, tb = exc_info()
            print '%s: ERROR %s' % (name, val.message)
            self.connection.send('%s: ERROR %s\n' % (name, val.message))

    def scandir(self, path):
        self.connection.send('%s: ERROR directory recursion not implemented\n' % path)

    def scan(self, path, name=None):
        if name is not None: return self.scanfile(path, name)
        if isfile(path): return self.scanfile(path, path)
        if isdir(path): return self.scandir(path)
        self.connection.send('%s: ERROR not a regular file or a directory\n' % path)

    def collect_incoming_data(self, data):
        client = self.connection.getpeername()
        data = data.strip()
        if data.startswith('SCAN '):
            self.do_SCAN(data.split('SCAN ', 1).pop())
        elif data.startswith('RAWSCAN '):
            self.do_RAWSCAN(data.split('RAWSCAN ', 1).pop())
        elif data == 'QUIT' or data == 'SHUTDOWN':
            self.do_QUIT()
        elif data == 'RELOAD':
            self.do_RELOAD()
        elif data == 'PING':
            self.do_PING()
        elif data.startswith('CONTSCAN '):
            self.do_CONTSCAN(data.split('CONTSCAN ', 1).pop())
        elif data == 'VERSION':
            self.do_VERSION()
        elif data == 'SESSION':
            self.do_SESSION(client)
        elif data == 'END':
            self.do_END(client)
        elif data == 'STREAM':
            self.do_STREAM()
        elif data.startswith('MULTISCAN '):
            self.do_MULTISCAN(data.split('MULTISCAN ', 1).pop())
        else:
            print 'Unknown command', data
            self.connection.send('UNKNOWN COMMAND\n')
        if not client in self.server.sessions: self.close()

    def do_SCAN(self, path):
        self.scan(path)

    def do_RAWSCAN(self, filename):
        self.connection.send('ERROR Not implemented\n')

    def do_QUIT(self):
        print 'Shutdown Requested'
        self.server.close()

    def do_RELOAD(self):
        self.connection.send('RELOADING\n')

    def do_PING(self):
        self.connection.send('PONG\n')

    def do_CONTSCAN(self, path):
        self.scan(path)

    def do_VERSION(self):
        version = pyc.getVersions()[0]
        self.connection.send(version + '\n')

    def do_STREAM(self):
        stream = socket(AF_INET, SOCK_STREAM)
        stream.settimeout(self.server.timeout)
        stream.bind((self.server.ip, 0))
        stream.listen(1)
        self.connection.send('PORT %d\n' % stream.getsockname()[1])

        try:
            conn, addr = stream.accept()
        except Exception, error:
            print 'Connection aborted', error
            self.connection.send('stream: ERROR %s\n' % error)
            stream.close()
            return

        f, filename = mkstemp()
        s = time()
        ok = True
        while True:
            r, w, e = select([conn], [], [], 1)
            n = time()
            if (n - s) > self.server.timeout:
                print 'Connection Timeout'
                self.connection.send('stream: ERROR timeout\n')
                ok = False
                break
            if r:
                try:
                    d = conn.recv(4096)
                    if not d: break
                    os_write(f, d)
                    s = n
                except Exception, error:
                    print 'Error Recv', error
                    self.connection.send('stream: ERROR %s\n' % error)
                    ok = False
                    break
            if e:
                print 'Error select()'
                self.connection.send('stream: Socket ERROR\n')
                ok = False
                break

        conn.close()
        os_close(f)
        stream.close()

        if ok: self.scan(filename, 'stream')

        try:
            unlink(filename)
        except:
            print 'Error unlinking tempfile'

    def do_SESSION(self, client):
        if client in self.server.sessions:
            self.connection.send('ERROR Session already started\n')
        else:
            self.server.sessions.append(client)

    def do_END(self, client):
        if not client in self.server.sessions:
            self.connection.send('ERROR Session not started\n')
        else:
            self.server.sessions.remove(client)

    def do_MULTISCAN(self, filename):
        self.connection.send('ERROR Not implemented\n')

class Server(dispatcher):
    def __init__(self, ip, port, handler, timeout=300):
        self.ip = ip
        self.port = port
        self.handler = handler
        self.timeout = timeout
        self.sessions = []
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
    s = Server('', port, CwdHandler)
    print "Cwd Server running on port %s" % port
    try:
        loop(timeout=1)
    except KeyboardInterrupt:
        print "Crtl+C pressed. Shutting down."
