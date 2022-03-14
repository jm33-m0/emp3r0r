"""
Module for accessing a Docker v2 Registry
"""

import base64
import hashlib
import json
import sys

try:
    import urllib.parse as urlparse
    from urllib.parse import urlencode
except ImportError:
    # pylint: disable=import-error,no-name-in-module,wrong-import-order
    from urllib import urlencode
    import urlparse

import ecdsa
import jws
import requests
import www_authenticate
# pylint: disable=wildcard-import
from dxf import exceptions

_schema2_mimetype = 'application/vnd.docker.distribution.manifest.v2+json'

if sys.version_info < (3, 0):
    _binary_type = str
else:
    _binary_type = bytes
    # pylint: disable=redefined-builtin
    long = int

def _to_bytes_2and3(s):
    return s if isinstance(s, _binary_type) else s.encode('utf-8')

def hash_bytes(buf):
    """
    Hash bytes using the same method the registry uses (currently SHA-256).

    :param buf: Bytes to hash
    :type buf: str

    :rtype: str
    :returns: Hex-encoded hash of file's content
    """
    sha256 = hashlib.sha256()
    sha256.update(buf)
    return sha256.hexdigest()

def hash_file(filename):
    """
    Hash a file using the same method the registry uses (currently SHA-256).

    :param filename: Name of file to hash
    :type filename: str

    :rtype: str
    :returns: Hex-encoded hash of file's content
    """
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def _raise_for_status(r):
    # pylint: disable=no-member
    if r.status_code == requests.codes.unauthorized:
        raise exceptions.DXFUnauthorizedError()
    r.raise_for_status()

class _ReportingFile(object):
    def __init__(self, dgst, f, cb):
        self._dgst = dgst
        self._f = f
        self._cb = cb
        self._size = requests.utils.super_len(f)
        cb(dgst, b'', self._size)
    # define __iter__ so requests thinks we're a stream
    # (models.py, PreparedRequest.prepare_body)
    def __iter__(self):
        assert not "called"
    # define fileno, tell and mode so requests can find length
    # (utils.py, super_len)
    def fileno(self):
        return self._f.fileno()
    def tell(self):
        return self._f.tell()
    @property
    def mode(self):
        return self._f.mode
    def read(self, n):
        chunk = self._f.read(n)
        if chunk:
            self._cb(self._dgst, chunk, self._size)
        return chunk

class DXFBase(object):
    # pylint: disable=too-many-instance-attributes
    """
    Class for communicating with a Docker v2 registry.
    Contains only operations which aren't related to repositories.

    Can act as a context manager. For each context entered, a new
    `requests.Session <http://docs.python-requests.org/en/latest/user/advanced/#session-objects>`_
    is obtained. Connections to the same host are shared by the session.
    When the context exits, all the session's connections are closed.

    If you don't use :class:`DXFBase` as a context manager, each request
    uses an ephemeral session. If you don't read all the data from an iterator
    returned by :meth:`DXF.pull_blob` then the underlying connection won't be
    closed until Python garbage collects the iterator.
    """
    def __init__(self, host, auth=None, insecure=False, auth_host=None):
        """
        :param host: Host name of registry. Can contain port numbers. e.g. ``registry-1.docker.io``, ``localhost:5000``.
        :type host: str

        :param auth: Authentication function to be called whenever authentication to the registry is required. Receives the :class:`DXFBase` object and a HTTP response object. It should call :meth:`authenticate` with a username, password and ``response`` before it returns.
        :type auth: function(dxf_obj, response)

        :param insecure: Use HTTP instead of HTTPS (which is the default) when connecting to the registry.
        :type insecure: bool

        :param auth_host: Host to use for token authentication. If set, overrides host returned by then registry.
        :type auth_host: str
        """
        self._base_url = ('http' if insecure else 'https') + '://' + host + '/v2/'
        self._auth = auth
        self._insecure = insecure
        self._auth_host = auth_host
        self._token = None
        self._headers = {}
        self._repo = None
        self._sessions = [requests]

    @property
    def token(self):
        """
        str: Authentication token. This will be obtained automatically when
        you call :meth:`authenticate`. If you've obtained a token
        previously, you can also set it but be aware tokens expire quickly.
        """
        return self._token

    @token.setter
    def token(self, value):
        self._token = value
        self._headers = {
            'Authorization': 'Bearer ' + value
        }

    def _base_request(self, method, path, **kwargs):
        def make_kwargs():
            r = {'allow_redirects': True}
            r.update(kwargs)
            if 'headers' not in r:
                r['headers'] = {}
            r['headers'].update(self._headers)
            return r
        url = urlparse.urljoin(self._base_url, path)
        r = getattr(self._sessions[0], method)(url, **make_kwargs())
        # pylint: disable=no-member
        if r.status_code == requests.codes.unauthorized and self._auth:
            headers = self._headers
            self._auth(self, r)
            if self._headers != headers:
                r = getattr(self._sessions[0], method)(url, **make_kwargs())
        _raise_for_status(r)
        return r

    def authenticate(self,
                     username=None, password=None,
                     actions=None, response=None,
                     authorization=None):
        # pylint: disable=too-many-arguments
        """
        Authenticate to the registry using a username and password,
        an authorization header or otherwise as the anonymous user.

        :param username: User name to authenticate as.
        :type username: str

        :param password: User's password.
        :type password: str

        :param actions: If you know which types of operation you need to make on the registry, specify them here. Valid actions are ``pull``, ``push`` and ``*``.
        :type actions: list

        :param response: When the ``auth`` function you passed to :class:`DXFBase`'s constructor is called, it is passed a HTTP response object. Pass it back to :meth:`authenticate` to have it automatically detect which actions are required.
        :type response: requests.Response

        :param authorization: ``Authorization`` header value.
        :type authorization: str

        :rtype: str
        :returns: Authentication token, if the registry supports bearer tokens. Otherwise ``None``, and HTTP Basic auth is used.
        """
        if self._insecure:
            raise exceptions.DXFAuthInsecureError()
        if response is None:
            response = self._sessions[0].get(self._base_url)
        # pylint: disable=no-member
        if response.status_code != requests.codes.unauthorized:
            raise exceptions.DXFUnexpectedStatusCodeError(response.status_code,
                                                          requests.codes.unauthorized)
        parsed = www_authenticate.parse(response.headers['www-authenticate'])
        if username is not None and password is not None:
            headers = {
                'Authorization': 'Basic ' + base64.b64encode(_to_bytes_2and3(username + ':' + password)).decode('utf-8')
            }
        elif authorization is not None:
            headers = {
                'Authorization': authorization
            }
        else:
            headers = {}
        if 'bearer' in parsed:
            info = parsed['bearer']
            if actions and self._repo:
                scope = 'repository:' + self._repo + ':' + ','.join(actions)
            else:
                scope = info['scope']
            url_parts = list(urlparse.urlparse(info['realm']))
            query = urlparse.parse_qs(url_parts[4])
            query.update({
                'service': info['service'],
                'scope': scope
            })
            url_parts[4] = urlencode(query, True)
            url_parts[0] = 'https'
            if self._auth_host:
                url_parts[1] = self._auth_host
            auth_url = urlparse.urlunparse(url_parts)
            r = self._sessions[0].get(auth_url, headers=headers)
            _raise_for_status(r)
            self.token = r.json()['token']
            return self._token
        else:
            self._headers = headers

    def list_repos(self):
        """
        List all repositories in the registry.

        :rtype: list
        :returns: List of repository names.
        """
        return self._base_request('get', '_catalog').json()['repositories']

    def __enter__(self):
        assert self._sessions
        session = requests.Session()
        session.__enter__()
        self._sessions.insert(0, session)
        return self

    def __exit__(self, *args):
        assert len(self._sessions) > 1
        session = self._sessions.pop(0)
        return session.__exit__(*args)

class DXF(DXFBase):
    """
    Class for operating on a Docker v2 repositories.
    """
    # pylint: disable=too-many-arguments
    def __init__(self, host, repo, auth=None, insecure=False, auth_host=None):
        """
        :param host: Host name of registry. Can contain port numbers. e.g. ``registry-1.docker.io``, ``localhost:5000``.
        :type host: str

        :param repo: Name of the repository to access on the registry. Typically this is of the form ``username/reponame`` but for your own registries you don't actually have to stick to that.
        :type repo: str

        :param auth: Authentication function to be called whenever authentication to the registry is required. Receives the :class:`DXF` object and a HTTP response object. It should call :meth:`DXFBase.authenticate` with a username, password and ``response`` before it returns.
        :type auth: function(dxf_obj, response)

        :param insecure: Use HTTP instead of HTTPS (which is the default) when connecting to the registry.
        :type insecure: bool

        :param auth_host: Host to use for token authentication. If set, overrides host returned by then registry.
        :type auth_host: str
        """
        super(DXF, self).__init__(host, auth, insecure, auth_host)
        self._repo = repo

    def _request(self, method, path, **kwargs):
        return super(DXF, self)._base_request(method, self._repo + '/' + path, **kwargs)

    def push_blob(self, filename, progress=None):
        """
        Upload a file to the registry and return its (SHA-256) hash.

        The registry is content-addressable so the file's content (aka blob)
        can be retrieved later by passing the hash to :meth:`pull_blob`.

        :param filename: File to upload.
        :type filename: str

        :param progress: Optional function to call as the upload progresses. The function will be called with the hash of the file's content, the blob just read from the file and the total size of the file.
        :type progress: function(dgst, chunk, total)

        :rtype: str
        :returns: Hash of file's content.
        """
        dgst = hash_file(filename)
        try:
            self._request('head', 'blobs/sha256:' + dgst)
            return dgst
        except requests.exceptions.HTTPError as ex:
            # pylint: disable=no-member
            if ex.response.status_code != requests.codes.not_found:
                raise
        r = self._request('post', 'blobs/uploads/')
        upload_url = r.headers['Location']
        url_parts = list(urlparse.urlparse(upload_url))
        query = urlparse.parse_qs(url_parts[4])
        query.update({'digest': 'sha256:' + dgst})
        url_parts[4] = urlencode(query, True)
        url_parts[0] = 'http' if self._insecure else 'https'
        upload_url = urlparse.urlunparse(url_parts)
        with open(filename, 'rb') as f:
            self._base_request('put',
                               upload_url,
                               data=_ReportingFile(dgst, f, progress) if progress else f)
        return dgst

    # pylint: disable=no-self-use
    def pull_blob(self, digest, size=False, chunk_size=None):
        """
        Download a blob from the registry given the hash of its content.

        :param digest: Hash of the blob's content.
        :type digest: str

        :param size: Whether to return the size of the blob too.
        :type size: bool

        :param chunk_size: Number of bytes to download at a time. Defaults to 8192.
        :type chunk_size: int

        :rtype: iterator
        :returns: If ``size`` is falsey, a byte string iterator over the blob's content. If ``size`` is truthy, a tuple containing the iterator and the blob's size.
        """
        if chunk_size is None:
            chunk_size = 8192
        r = self._request('get', 'blobs/sha256:' + digest, stream=True)
        # pylint: disable=too-few-public-methods
        class Chunks(object):
            def __iter__(self):
                sha256 = hashlib.sha256()
                for chunk in r.iter_content(chunk_size):
                    sha256.update(chunk)
                    yield chunk
                dgst = sha256.hexdigest()
                if dgst != digest:
                    raise exceptions.DXFDigestMismatchError(dgst, digest)
        return (Chunks(), long(r.headers['content-length'])) if size else Chunks()

    def blob_size(self, digest):
        """
        Return the size of a blob in the registry given the hash of its content.

        :param digest: Hash of the blob's content.
        :type digest: str

        :rtype: long
        :returns: Whether the blob exists.
        """
        r = self._request('head', 'blobs/sha256:' + digest)
        return long(r.headers['content-length'])

    def del_blob(self, digest):
        """
        Delete a blob from the registry given the hash of its content.

        :param digest: Hash of the blob's content.
        :type digest: str
        """
        self._request('delete', 'blobs/sha256:' + digest)

    # For dtuf; highly unlikely anyone else will want this
    def make_manifest(self, *digests):
        layers = [{
            'mediaType': 'application/octet-stream',
            'size': self.blob_size(dgst),
            'digest': 'sha256:' + dgst
        } for dgst in digests]
        return json.dumps({
            'schemaVersion': 2,
            'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
            # V2 Schema 2 insists on a config dependency. We're just using the
            # registry as a blob store so to save us uploading extra blobs,
            # use the first layer.
            'config': {
                'mediaType': 'application/octet-stream',
                'size': layers[0]['size'],
                'digest': layers[0]['digest']
            },
            'layers': layers
        }, sort_keys=True)

    def set_alias(self, alias, *digests):
        # pylint: disable=too-many-locals
        """
        Give a name (alias) to a set of blobs. Each blob is specified by
        the hash of its content.

        :param alias: Alias name
        :type alias: str

        :param digests: List of blob hashes (strings).
        :type digests: list

        :rtype: str
        :returns: The registry manifest used to define the alias. You almost definitely won't need this.
        """
        try:
            manifest_json = self.make_manifest(*digests)
            self._request('put',
                          'manifests/' + alias,
                          data=manifest_json,
                          headers={'Content-Type': _schema2_mimetype})
            return manifest_json
        except requests.exceptions.HTTPError as ex:
            # pylint: disable=no-member
            if ex.response.status_code != requests.codes.bad_request:
                raise
            manifest_json = self.make_unsigned_manifest(alias, *digests)
            signed_json = _sign_manifest(manifest_json)
            self._request('put', 'manifests/' + alias, data=signed_json)
            return signed_json

    def get_alias(self,
                  alias=None,
                  manifest=None,
                  verify=True,
                  sizes=False):
        """
        Get the blob hashes assigned to an alias.

        :param alias: Alias name. You almost definitely will only need to pass this argument.
        :type alias: str

        :param manifest: If you previously obtained a manifest, specify it here instead of ``alias``. You almost definitely won't need to do this.
        :type manifest: str

        :param verify: (v1 schema only) Whether to verify the integrity of the alias definition in the registry itself. You almost definitely won't need to change this from the default (``True``).
        :type verify: bool

        :param sizes: Whether to return sizes of the blobs along with their hashes
        :type sizes: bool

        :rtype: list
        :returns: If ``sizes`` is falsey, a list of blob hashes (strings) which are assigned to the alias. If ``sizes`` is truthy, a list of (hash,size) tuples for each blob.
        """
        if alias:
            r = self._request('get',
                              'manifests/' + alias,
                              headers={'Accept': _schema2_mimetype + ', ' +
                                                 _schema1_mimetype})
            manifest = r.content.decode('utf-8')
            dcd = r.headers['docker-content-digest']
        else:
            dcd = None
        parsed_manifest = json.loads(manifest)
        if parsed_manifest['schemaVersion'] == 1:
            dgsts = _verify_manifest(manifest, parsed_manifest, dcd, verify)
            if not sizes:
                return dgsts
            return [(dgst, self.blob_size(dgst)) for dgst in dgsts]
        else:
            if dcd:
                method, expected_dgst = dcd.split(':')
                if method != 'sha256':
                    raise exceptions.DXFUnexpectedDigestMethodError(method, 'sha256')
                hasher = hashlib.new(method)
                hasher.update(r.content)
                dgst = hasher.hexdigest()
                if dgst != expected_dgst:
                    raise exceptions.DXFDigestMismatchError(dgst, expected_dgst)

            r = []
            for layer in parsed_manifest['layers']:
                method, dgst = layer['digest'].split(':')
                if method != 'sha256':
                    raise exceptions.DXFUnexpectedDigestMethodError(method, 'sha256')
                r.append((dgst, layer['size']) if sizes else dgst)
            return r

    def _get_dcd(self, alias):
        '''get the Docker Content Digest ID

        :param str alias: alias name
        :rtype: str
        '''
        # https://docs.docker.com/registry/spec/api/#deleting-an-image
        # Note When deleting a manifest from a registry version 2.3 or later,
        # the following header must be used when HEAD or GET-ing the manifest
        # to obtain the correct digest to delete:
        # Accept: application/vnd.docker.distribution.manifest.v2+json
        return self._request(
            'head',
            'manifests/{}'.format(alias),
            headers={'Accept': _schema2_mimetype},
        ).headers.get('Docker-Content-Digest')

    def del_alias(self, alias):
        """
        Delete an alias from the registry. The blobs it points to won't be deleted. Use :meth:`del_blob` for that.

        .. Note::
           On private registry, garbage collection might need to be run manually; see:
           https://docs.docker.com/registry/garbage-collection/

        :param alias: Alias name.
        :type alias: str

        :rtype: list
        :returns: A list of blob hashes (strings) which were assigned to the alias.
        """
        dcd = self._get_dcd(alias)
        dgsts = self.get_alias(alias)
        self._request('delete', 'manifests/{}'.format(dcd))
        return dgsts

    def list_aliases(self):
        """
        List all aliases defined in the repository.

        :rtype: list
        :returns: List of alias names (strings).
        """
        return self._request('get', 'tags/list').json()['tags']

# v1 schema support functions below

    def make_unsigned_manifest(self, alias, *digests):
        return json.dumps({
            'schemaVersion': 1,
            'name': self._repo,
            'tag': alias,
            'fsLayers': [{'blobSum': 'sha256:' + dgst} for dgst in digests],
            'history': [{'v1Compatibility': '{}'} for dgst in digests]
        }, sort_keys=True)

_schema1_mimetype = 'application/vnd.docker.distribution.manifest.v1+json'

def _urlsafe_b64encode(s):
    return base64.urlsafe_b64encode(_to_bytes_2and3(s)).rstrip(b'=').decode('utf-8')

def _pad64(s):
    return s + b'=' * (-len(s) % 4)

def _urlsafe_b64decode(s):
    return base64.urlsafe_b64decode(_pad64(_to_bytes_2and3(s)))

def _num_to_base64(n):
    b = bytearray()
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    # need to pad to 32 bytes
    while len(b) < 32:
        b.insert(0, 0)
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('utf-8')

def _base64_to_num(s):
    b = bytearray(_urlsafe_b64decode(s))
    m = len(b) - 1
    return sum((1 << ((m - bi)*8)) * bb for (bi, bb) in enumerate(b))

def _jwk_to_key(jwk):
    if jwk['kty'] != 'EC':
        raise exceptions.DXFUnexpectedKeyTypeError(jwk['kty'], 'EC')
    if jwk['crv'] != 'P-256':
        raise exceptions.DXFUnexpectedKeyTypeError(jwk['crv'], 'P-256')
    # pylint: disable=bad-continuation
    return ecdsa.VerifyingKey.from_public_point(
            ecdsa.ellipticcurve.Point(ecdsa.NIST256p.curve,
                                      _base64_to_num(jwk['x']),
                                      _base64_to_num(jwk['y'])),
            ecdsa.NIST256p)

def _sign_manifest(manifest_json):
    manifest64 = _urlsafe_b64encode(manifest_json)
    format_length = manifest_json.rfind('}')
    format_tail = manifest_json[format_length:]
    protected_json = json.dumps({
        'formatLength': format_length,
        'formatTail': _urlsafe_b64encode(format_tail)
    })
    protected64 = _urlsafe_b64encode(protected_json)
    key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    point = key.privkey.public_key.point
    data = {
        'key': key,
        'header': {
            'alg': 'ES256'
        }
    }
    jws.header.process(data, 'sign')
    sig = data['signer']("%s.%s" % (protected64, manifest64), key)
    signatures = [{
        'header': {
            'jwk': {
                'kty': 'EC',
                'crv': 'P-256',
                'x': _num_to_base64(point.x()),
                'y': _num_to_base64(point.y())
            },
            'alg': 'ES256'
        },
        'signature': _urlsafe_b64encode(sig),
        'protected': protected64
    }]
    return manifest_json[:format_length] + \
           ', "signatures": ' + json.dumps(signatures) + \
           format_tail

def _verify_manifest(content,
                     manifest,
                     content_digest=None,
                     verify=True):
    # pylint: disable=too-many-locals,too-many-branches

    # Adapted from https://github.com/joyent/node-docker-registry-client

    if verify or ('signatures' in manifest):
        signatures = []
        for sig in manifest['signatures']:
            protected64 = sig['protected']
            protected = _urlsafe_b64decode(protected64).decode('utf-8')
            protected_header = json.loads(protected)

            format_length = protected_header['formatLength']
            format_tail64 = protected_header['formatTail']
            format_tail = _urlsafe_b64decode(format_tail64).decode('utf-8')

            alg = sig['header']['alg']
            if alg.lower() == 'none':
                raise exceptions.DXFDisallowedSignatureAlgorithmError('none')
            if sig['header'].get('chain'):
                raise exceptions.DXFSignatureChainNotImplementedError()

            signatures.append({
                'alg': alg,
                'signature': sig['signature'],
                'protected64': protected64,
                'key': _jwk_to_key(sig['header']['jwk']),
                'format_length': format_length,
                'format_tail': format_tail
            })

        payload = content[:signatures[0]['format_length']] + \
                  signatures[0]['format_tail']
        payload64 = _urlsafe_b64encode(payload)
    else:
        payload = content

    if content_digest:
        method, expected_dgst = content_digest.split(':')
        if method != 'sha256':
            raise exceptions.DXFUnexpectedDigestMethodError(method, 'sha256')
        hasher = hashlib.new(method)
        hasher.update(payload.encode('utf-8'))
        dgst = hasher.hexdigest()
        if dgst != expected_dgst:
            raise exceptions.DXFDigestMismatchError(dgst, expected_dgst)

    if verify:
        for sig in signatures:
            data = {
                'key': sig['key'],
                'header': {
                    'alg': sig['alg']
                }
            }
            jws.header.process(data, 'verify')
            sig64 = sig['signature']
            data['verifier']("%s.%s" % (sig['protected64'], payload64),
                             _urlsafe_b64decode(sig64),
                             sig['key'])

    dgsts = []
    for layer in manifest['fsLayers']:
        method, dgst = layer['blobSum'].split(':')
        if method != 'sha256':
            raise exceptions.DXFUnexpectedDigestMethodError(method, 'sha256')
        dgsts.append(dgst)
    return dgsts

jws.utils.to_bytes_2and3 = _to_bytes_2and3
jws.algos.to_bytes_2and3 = _to_bytes_2and3
