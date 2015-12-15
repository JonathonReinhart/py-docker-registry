#!/usr/bin/env python
# References:
#   https://github.com/kwk/docker-registry-setup#manual-token-based-workflow-to-list-repositories
#   https://docs.docker.com/registry/spec/api
#   http://docs.python-requests.org/en/latest/user/authentication/#new-forms-of-authentication

from __future__ import print_function
import sys
import requests
from requests.auth import AuthBase, HTTPBasicAuth

__all__ = ['Registry', 'RegistryError', 'AuthenticationError']

class BearerAuth(AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, req):
        req.headers['Authorization'] = 'Bearer {}'.format(self.token)
        return req


class RegistryError(Exception):
    def __init__(self, message, code=None, detail=None):
        super(RegistryError, self).__init__(message)
        self.code = code
        self.detail = detail

    @classmethod
    def from_json(cls, json):
        '''Encapsulate an error response in an exception

        Arguments:
            json: the JSON data returned by the API request
        '''
        errors = json.get('errors')
        if not errors or len(errors) == 0:
            return cls('Unknown error!')

        # For simplicity, we'll just include the first error.
        err = errors[0]
        return cls(
            message = err.get('message'),
            code = err.get('code'),
            detail = err.get('detail'),
        )




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

        # We keep just the last-used token around, to prevent unnecessary
        # requests both with the registry and auth server.
        # It is yet to be seen how well this single-entry cache performs
        # across varying scopes of API calls.
        self.auth = None

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
        params = {k:v for k,v in info.iteritems() if k in ('service','scope')}
        auth = HTTPBasicAuth(self.username, self.password)
        r2 = requests.get(info['realm'], params=params, auth=auth, verify=self.verify_ssl)

        if r2.status_code == 401:
            raise AuthenticationError()
        r2.raise_for_status()

        self.auth = BearerAuth(r2.json()['token'])

    def _do_get(self, endpoint):
        url = '{0}/v2/{1}'.format(self.url, endpoint)

        # Try to use previous bearer token
        r = requests.get(url, auth=self.auth, verify=self.verify_ssl)

        # If necessary, try to authenticate and try again
        if r.status_code == 401:
            self._authenticate_for(r)
            r = requests.get(url, auth=self.auth, verify=self.verify_ssl)

        json = r.json()

        if r.status_code != 200:
            raise RegistryError.from_json(json)

        return json

    def get_tags(self, name):
        endpoint = '{name}/tags/list'.format(name=name)
        return self._do_get(endpoint)

    def get_manifest(self, name, ref):
        endpoint = '{name}/manifests/{ref}'.format(name=name, ref=ref)
        return self._do_get(endpoint)

    def get_catalog(self):
        return self._do_get('_catalog')

    def api_test(self):
        return self._do_get('')
