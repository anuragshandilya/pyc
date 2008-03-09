#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4 -*-
#
# Simple Clone of Clamd using pyc extension
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
from os import walk, unlink, write as os_write, close as os_close
from os.path import isfile, isdir, join as path_join
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

    def scanfile(self, filename):
        try:
            infected, virus = pyc.scanFile(filename)
        except:
            t, val, tb = exc_info()
            return True, 'ERROR', val.message
        return True, infected, virus

    def sendreply(self, res, name, infected, virusname):
        try:
            if not res:
                print '%s: ERROR %s' % (name, virusname)
                self.connection.send('%s: ERROR %s\n' % (name, virusname))
                return False
            if infected:
                print '%s: %s FOUND' % (name, virusname)
                self.connection.send('%s: %s FOUND\n' % (name, virusname))
            else:
                self.connection.send('%s: OK\n' % name)
            return True
        except Exception, error:
            t, val, tb = exc_info()
            print 'Error sending reply', error
            return False

    def scan(self, path, name=None, cont=False):
        ## FIXME: stat() in pyc.c does not like unc paths
        ## on win32 is almost impossible to pass an fd from py to libclamav
        ## due to crt hell with posix layer
        if path.startswith('\\\\?\\'):
            path = path.split('\\\\?\\', 1).pop()

        if (name is not None):
            res, infected, virusname = self.scanfile(path)
            return self.sendreply(res, name, infected, virusname)
        elif isfile(path):
            res, infected, virusname = self.scanfile(path)
            return self.sendreply(res, path, infected, virusname)
        elif isdir(path):
            for f in walk(path):
                for child in f[2]:
                    filename = path_join(f[0], child)
                    res, infected, virusname = self.scanfile(filename)
                    if not self.sendreply(res, filename, infected, virusname): return
                    if not cont: return
        else:
            self.connection.send('%s: ERROR not a regular file or directory\n' % path)

    def collect_incoming_data(self, cmd):
        client = self.connection.getpeername()
        print 'Connection from:', client[0]
        cmd = cmd.strip()
        if cmd.startswith('SCAN '):
            self.do_SCAN(cmd.split('SCAN ', 1).pop())
        elif cmd.startswith('RAWSCAN '):
            self.do_RAWSCAN(cmd.split('RAWSCAN ', 1).pop())
        elif cmd == 'QUIT' or cmd == 'SHUTDOWN':
            self.do_QUIT()
        elif cmd == 'RELOAD':
            self.do_RELOAD()
        elif cmd == 'PING':
            self.do_PING()
        elif cmd.startswith('CONTSCAN '):
            self.do_CONTSCAN(cmd.split('CONTSCAN ', 1).pop())
        elif cmd == 'VERSION':
            self.do_VERSION()
        elif cmd == 'SESSION':
            self.do_SESSION(client)
        elif cmd == 'END':
            self.do_END(client)
        elif cmd == 'STREAM':
            self.do_STREAM()
        elif cmd.startswith('MULTISCAN '):
            self.do_MULTISCAN(cmd.split('MULTISCAN ', 1).pop())
        else:
            print 'Unknown command', cmd
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
        self.scan(path, cont=True)

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
