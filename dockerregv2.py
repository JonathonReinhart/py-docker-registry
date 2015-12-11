#!/usr/bin/env python
# References:
#   https://github.com/kwk/docker-registry-setup#manual-token-based-workflow-to-list-repositories
#   https://docs.docker.com/registry/spec/api

from __future__ import print_function
import sys
import requests
from requests.auth import HTTPBasicAuth

class RegistryError(Exception):
    def __init__(self, json):
        '''Encapsulate an error response in an exception

        Arguments:
            json: the JSON data returned by the API request
        '''
        # Sample json data:
        #
        #   {u'errors': [{u'message': u'repository name not known to registry',
        #                 u'code': u'NAME_UNKNOWN', u'detail': {u'name': u'example'}}]}
        #
        # For simplicity, we'll just include the first error.
        message = 'Unknown error!'
        errors = json.get('errors')
        if errors:
            message = errors[0].get('message')
        super(RegistryError, self).__init__(message)

class AuthenticationError(Exception):
    pass

class Registry(object):
    def __init__(self, url, username, password, verify_ssl=False):
        url = url.rstrip('/')
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url
        self.url = url

        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.bearer_token = None

    def authenticate(self):
        '''Forcefully auth for testing'''
        r = requests.head(self.url + '/v2/', verify=self.verify_ssl)
        self._authenticate_for(r)


    def _authenticate_for(self, resp):
        '''Authenticate to satsify the unauthorized response
        '''
        # Get the auth. info from the headers
        scheme, params = resp.headers['Www-Authenticate'].split(None, 1)
        assert(scheme == 'Bearer')
        info = {k:v.strip('"') for k,v in (i.split('=') for i in params.split(','))}

        # Request a token from the auth server
        params = {k:v for k,v in info.iteritems() if k != 'realm'}
        auth = HTTPBasicAuth(self.username, self.password)
        r2 = requests.get(info['realm'], params=params, auth=auth, verify=self.verify_ssl)

        if r2.status_code == 401:
            raise AuthenticationError()
        r2.raise_for_status()

        self.bearer_token = r2.json()['token']

    def _do_get(self, endpoint):
        url = '{0}/v2/{1}'.format(self.url, endpoint)
        headers = {}

        # Try to use previous bearer token
        if self.bearer_token:
            headers['Authorization'] = 'Bearer {}'.format(self.bearer_token)

        r = requests.get(url, headers=headers, verify=self.verify_ssl)

        # If necessary, try to authenticate and try again
        if r.status_code == 401:
            self._authenticate_for(r)

            assert(self.bearer_token)
            headers['Authorization'] = 'Bearer {}'.format(self.bearer_token)

            r = requests.get(url, headers=headers, verify=self.verify_ssl)

        json = r.json()

        if r.status_code != 200:
            #print('Error: {0}'.format(json), file=sys.stderr)
            raise RegistryError(json)

        return json

    def get_tags(self, name):
        endpoint = name + '/tags/list'
        return self._do_get(endpoint)

    def get_catalog(self):
        return self._do_get('/_catalog')

    def api_test(self):
        return self._do_get('/')
