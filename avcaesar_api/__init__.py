#      __      __   _____
#     /\ \    / /  / ____|
#    /  \ \  / /  | |     __ _  ___  ___  __ _ _ __
#   / /\ \ \/ /   | |    / _` |/ _ \/ __|/ _` | '__|
#  / ____ \  /    | |___| (_| |  __/\__ \ (_| | |
# /_/    \_\/      \_____\__,_|\___||___/\__,_|_|
#
import os
import re
import io
import hashlib
import requests
from distutils.version import StrictVersion

if StrictVersion(requests.__version__) < StrictVersion('1.0.0'):
    raise ImportError('The version of the requests library should be 1.0.0 or higher')

__version__ = "1.0.1"
config_malware_lu = {
    'url': "https://avcaesar.malware.lu/api",
    'server_cert': os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'malware_lu.crt'))
}


class SampleAlreadyExistsException(Exception):
    def __init__(self, file_hash):
        self.file_hash = file_hash

    def __str__(self):
        return "Hash %s already in database" % self.file_hash


class UnexpectedServerResponseException(Exception):
    def __init__(self, response):
        if not isinstance(response, requests.Response):
            raise TypeError("response must a requests.Response instance.")
        self.response = response

    def __str__(self):
        return "Status code: %s; Content-type: %s; Content: %s" % (
            self.response.status_code,
            self.response.headers['content-type'],
            self.response.content
        )


class NotFoundException(Exception):
    pass


class ResourceLockedException(Exception):
    def __init__(self, data):
        super().__init__()
        self.data = data


class Connector():
    def __init__(self, url=None, key=None, server_cert=None):
        if not isinstance(url, str):
            raise TypeError("url must be a unicode string")
        self.url_base = "%s/v1" % url
        self.configuration = {
            'cookies': dict()
        }
        if server_cert:
            self.configuration['verify'] = server_cert
        if key:
            self.configuration['cookies']['apikey'] = key

    def download(self, reference):
        resp = requests.get("%s/sample/%s/download" % (self.url_base, reference), **self.configuration)
        if resp.ok:
            filename = re.findall(
                'filename=(\S+)',
                resp.headers.get('content-disposition'))[0]
            payload = resp.content
            return payload, filename
        elif resp.status_code != 404:
            raise UnexpectedServerResponseException(resp)
        return None, None

    def info(self, reference, private=False):
        if private:
            url = "%s/sample/private/%s" % (self.url_base, reference)
        else:
            url = "%s/sample/%s" % (self.url_base, reference)
        resp = requests.get(url, **self.configuration)
        if resp.ok:
            return resp.json()
        elif resp.status_code == 404:
            raise NotFoundException()
        raise UnexpectedServerResponseException(resp)

    def has_sample_hash(self, sample_hash, page=1, per_page=1):
        resp = requests.get(
            "%s/sample/has_hash/%s" % (self.url_base, sample_hash),
            params={'page': page, 'per_page': per_page},
            **self.configuration
        )
        if resp.ok:
            return resp.json()
        elif resp.status_code == 404:
            return None
        raise UnexpectedServerResponseException(resp)

    def has_private_sample_hash(self, sample_hash):
        resp = requests.get("%s/sample/private/has_hash/%s" % (self.url_base, sample_hash), **self.configuration)
        if resp.ok:
            return resp.json()
        raise UnexpectedServerResponseException(resp)

    def quota(self):
        resp = requests.get("%s/user/quota" % self.url_base, **self.configuration)
        if not resp.ok:
            raise UnexpectedServerResponseException(resp)
        return resp.json()

    def is_authenticated(self):
        resp = requests.get("%s/user/is_authenticated" % self.url_base, **self.configuration)
        if not resp.ok:
            raise UnexpectedServerResponseException(resp)
        return resp.json()

    def upload(self, payload, name=None, private=False):
        if not isinstance(payload, io.IOBase):
            raise TypeError("payload must be an instance of IOBase subclass.")
        if isinstance(payload, io.BufferedIOBase):
            files = {'file': payload}
        else:
            if name is None:
                name = self.sha256sum(payload)
            payload.seek(0)
            files = {'file': (name, payload)}
        if private:
            url = "%s/sample/private/upload" % self.url_base
        else:
            url = "%s/sample/upload" % self.url_base
        resp = requests.post(
            url,
            files=files,
            **self.configuration
        )
        if not resp.ok:
            if resp.status_code == 423:
                raise ResourceLockedException(resp.json())
            else:
                raise UnexpectedServerResponseException(resp)
        return resp.json()

    def delete(self, reference, private=False):
        if private:
            url = "%s/sample/private/%s/delete" % (self.url_base, reference)
        else:
            raise NotImplemented()

        resp = requests.get(url, **self.configuration)

        if resp.ok:
            return resp.json()
        elif resp.status_code == 404:
            raise NotFoundException()
        else:
            raise UnexpectedServerResponseException(resp)

    def update(self, reference):
        resp = requests.get("%s/sample/%s/update" % (self.url_base, reference), **self.configuration)
        if resp.ok:
            return resp.json()
        elif resp.status_code == 404:
            raise NotFoundException()
        elif resp.status_code == 423:
            raise ResourceLockedException(resp.json())
        raise UnexpectedServerResponseException(resp)

    def history_analysis(self, private=False, page=1, per_page=20):
        if private:
            url = "%s/user/history/private_analysis" % self.url_base
        else:
            url = "%s/user/history/analysis" % self.url_base
        resp = requests.get(url, params={'page': page, 'per_page': per_page}, **self.configuration)
        if resp.ok:
            return resp.json()
        raise UnexpectedServerResponseException(resp)

    @staticmethod
    def sha256sum(payload):
        if not isinstance(payload, io.IOBase):
            raise TypeError("payload must be a subclass of IOBase")
        sha256 = hashlib.sha256()
        for chunk in iter(lambda: payload.read(128*sha256.block_size), b''):
            sha256.update(chunk)
        return sha256.hexdigest()
