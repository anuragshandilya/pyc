#!/usr/bin/env python
import pyc

pyc.setEngineOption('tempdir', '/tmp/z')
pyc.setEngineOption('leave-temps', True)
pyc.loadDB()
print pyc.getVersions()
print pyc.getScanOptions()
print pyc.scanFile('/tmp/clam.exe')
