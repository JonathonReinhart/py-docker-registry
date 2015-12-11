#!/usr/bin/env python
from __future__ import print_function
import sys
import argparse
import getpass
import logging
from cmd import Cmd
import readline

import dockerregv2

class RegistryConsole(Cmd):
    def __init__(self, reg):
        self.reg = reg
        self.prompt = '[{0}] Registry: '.format(reg.url.split('//')[1])
        Cmd.__init__(self)

    def do_EOF(self, line):
        return self.do_quit(line)

    def do_quit(self, line):
        '''Quit the interactive console'''
        return True

    def do_catalog(self, line):
        '''Get the registry catalog'''
        catalog = self.reg.get_catalog()
        print('Repositories:')
        for r in catalog['repositories']:
            print('   ' + r)



def enable_requests_debugging():
    # http://stackoverflow.com/a/16630836
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client
    http_client.HTTPConnection.debuglevel = 1

    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

def parse_args():
    ap = argparse.ArgumentParser(description='Docker Registry v2 API console')
    ap.add_argument('registry_url',
            help = 'URL of registry (e.g. https://registry.example.com)')
    ap.add_argument('-u', '--user', dest = 'username',
            help = 'username for authentication')
    ap.add_argument('-p', '--password',
            help = 'password for authentication')
    ap.add_argument('-d', '--debug', action = 'store_true',
            help = 'enable debugging')
    return ap.parse_args()

def main():
    args = parse_args()

    if args.debug:
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        enable_requests_debugging()


    if not args.username:
        args.username = raw_input('Username: ')
    if not args.password:
        args.password = getpass.getpass('Password: ')

    reg = dockerregv2.Registry(
        url = args.registry_url,
        username = args.username,
        password = args.password,
        verify_ssl = '/etc/ssl/certs/ca-bundle.crt')

    reg.api_test()

    RegistryConsole(reg).cmdloop()

if __name__ == '__main__':
    main()

