"""Read-only GitHub App source adapter; live installation proof is still required."""
import base64
import binascii
import hashlib
import json
import os
import re
import time
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, HTTPRedirectHandler, ProxyHandler, build_opener

import jwt
from apishield_agent.domain.contract_input import MAX_CONTRACT_BYTES, load_contract

MAX_RESPONSE = 4 * 1024 * 1024


class SourceError(ValueError):
    """Only non-sensitive bounded error codes are exposed/persisted."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SourceError('GITHUB_REDIRECT_DISABLED')


def transport(method, url, headers, body):
    if not url.startswith('https://api.github.com/'):
        raise SourceError('GITHUB_HOST_DISABLED')
    opener = build_opener(ProxyHandler({}), NoRedirect())
    request = Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(request, timeout=10) as response:
            content = response.read(MAX_RESPONSE + 1)
            if len(content) > MAX_RESPONSE:
                raise SourceError('GITHUB_RESPONSE_TOO_LARGE')
            return response.status, json.loads(content)
    except HTTPError as error:
        raise SourceError(f'GITHUB_HTTP_{error.code}') from None
    except (URLError, OSError, ValueError, RecursionError, UnicodeError) as error:
        if isinstance(error, SourceError):
            raise
        raise SourceError('GITHUB_TRANSPORT_FAILURE') from None


class GitHubSources:
    def __init__(self, app_id, private_key, mappings, send=transport):
        if not re.fullmatch(r'[A-Za-z0-9._-]{1,100}', str(app_id)):
            raise SourceError('GITHUB_APP_CONFIGURATION_INVALID')
        self.app_id, self.private_key, self.mappings, self.send = str(app_id), private_key, mappings, send

    @classmethod
    def from_environment(cls):
        if os.getenv('APISHIELD_GITHUB_READS_ENABLED') != '1':
            return None
        try:
            raw = os.environ['APISHIELD_GITHUB_SOURCE_MAP_JSON']
            if len(raw.encode()) > 65536:
                raise ValueError('limit')
            def unique_pairs(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('duplicate mapping key')
                    result[key] = value
                return result

            mappings = json.loads(raw, object_pairs_hook=unique_pairs)
            if not isinstance(mappings, dict):
                raise ValueError('shape')
            return cls(os.environ['APISHIELD_GITHUB_APP_ID'], os.environ['APISHIELD_GITHUB_APP_PRIVATE_KEY'], mappings)
        except (KeyError, ValueError):
            raise SourceError('GITHUB_APP_CONFIGURATION_REQUIRED') from None

    def request(self, method, path, token, body=None):
        headers={'Accept':'application/vnd.github+json', 'Authorization':f'Bearer {token}', 'X-GitHub-Api-Version':'2026-03-10', 'User-Agent':'ForgeWorks-APIShield'}
        if body is not None:
            headers['Content-Type']='application/json'
        status, result = self.send(method, 'https://api.github.com' + path, headers, json.dumps(body).encode() if body is not None else None)
        if status not in {200,201} or not isinstance(result, dict):
            raise SourceError(f'GITHUB_RESPONSE_REJECTED_{status}')
        return result

    def installation_token(self, installation, repository_id):
        timestamp = int(time.time())
        try:
            signed = jwt.encode({'iss':self.app_id,'iat':timestamp-60,'exp':timestamp+540}, self.private_key, algorithm='RS256')
        except Exception:
            raise SourceError('GITHUB_SIGNING_CONFIGURATION_INVALID') from None
        result = self.request('POST', f'/app/installations/{installation}/access_tokens', signed, {'repository_ids':[repository_id], 'permissions':{'contents':'read'}})
        permissions = result.get('permissions', {})
        if not isinstance(permissions, dict) or permissions.get('contents') != 'read' or any(key not in {'contents','metadata'} or value != 'read' for key,value in permissions.items()):
            raise SourceError('GITHUB_TOKEN_PERMISSION_MISMATCH')
        # The requested repository_ids constraint must be reflected in the
        # minted token response, not merely in the outgoing request. A broader
        # token is forbidden even if its permissions remain read-only.
        repositories = result.get('repositories')
        if (result.get('repository_selection') != 'selected'
                or not isinstance(repositories, list)
                or len(repositories) != 1
                or not isinstance(repositories[0], dict)
                or type(repositories[0].get('id')) is not int
                or repositories[0]['id'] != repository_id):
            raise SourceError('GITHUB_TOKEN_REPOSITORY_SCOPE_MISMATCH')
        try:
            expires_at = result['expires_at']
            if not isinstance(expires_at, str):
                raise ValueError('expiry type')
            expiry = datetime.fromisoformat(expires_at.replace('Z','+00:00'))
            if expiry.tzinfo is None or not timestamp+30 < expiry.timestamp() <= timestamp+3660:
                raise ValueError('expiry')
            token = result['token']
            if not isinstance(token, str) or not token or len(token) > 4096 or any(ord(c)<33 for c in token):
                raise ValueError('token')
        except (KeyError, ValueError, TypeError, OverflowError):
            raise SourceError('GITHUB_TOKEN_RESPONSE_INVALID') from None
        return token

    def content(self, full_name, path, revision, token):
        if not isinstance(revision, str) or not re.fullmatch(r'[0-9a-fA-F]{40}', revision):
            raise SourceError('GITHUB_IMMUTABLE_REVISION_REQUIRED')
        encoded = '/'.join(quote(part, safe='') for part in path.split('/'))
        result = self.request('GET', f'/repos/{full_name}/contents/{encoded}?ref={revision}', token)
        if result.get('type') != 'file' or result.get('encoding') != 'base64' or result.get('path') != path or result.get('submodule_git_url'):
            raise SourceError('GITHUB_SOURCE_NOT_REGULAR_FILE')
        size = result.get('size')
        if type(size) is not int or not 0 < size <= MAX_CONTRACT_BYTES:
            raise SourceError('GITHUB_SOURCE_SIZE_INVALID')
        try:
            encoded_body = result['content']
            if not isinstance(encoded_body,str) or len(encoded_body)>MAX_RESPONSE:
                raise ValueError('encoding')
            body = base64.b64decode(''.join(encoded_body.split()), validate=True)
        except (KeyError, ValueError, TypeError, binascii.Error):
            raise SourceError('GITHUB_SOURCE_ENCODING_INVALID') from None
        blob_sha = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
        if len(body) != size or result.get('sha') != blob_sha:
            raise SourceError('GITHUB_BLOB_INTEGRITY_FAILURE')
        load_contract(body)
        return body

    def snapshot(self, analysis, repository):
        key = analysis['tenant_id'] + ':' + analysis['repository_id']
        mapping = self.mappings.get(key)
        if not isinstance(mapping,dict):
            raise SourceError('GITHUB_SOURCE_MAPPING_REQUIRED')
        full_name, path = mapping.get('full_name',''), mapping.get('contract_path','')
        if not isinstance(full_name,str) or not re.fullmatch(r'[A-Za-z0-9-]{1,100}/[A-Za-z0-9._-]{1,100}',full_name):
            raise SourceError('GITHUB_REPOSITORY_MAPPING_INVALID')
        if not isinstance(path,str) or not path or len(path)>1024 or any(part in {'','.', '..'} for part in path.split('/')) or '\\' in path or any(ord(c)<32 for c in path):
            raise SourceError('GITHUB_CONTRACT_PATH_INVALID')
        installation, repository_id = mapping.get('installation_id'), mapping.get('repository_id')
        if type(installation) is not int or installation<=0 or installation != repository['installation_id'] or type(repository_id) is not int or repository_id<=0:
            raise SourceError('GITHUB_INSTALLATION_BINDING_INVALID')
        # Reject mutable refs before any network/token minting.
        try:
            revisions = (analysis['base_sha'], analysis['head_sha'])
        except (KeyError, IndexError, TypeError):
            raise SourceError('GITHUB_IMMUTABLE_REVISION_REQUIRED') from None
        if any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{40}', value) for value in revisions):
            raise SourceError('GITHUB_IMMUTABLE_REVISION_REQUIRED')
        token = self.installation_token(installation, repository_id)
        metadata = self.request('GET', f'/repos/{full_name}', token)
        if type(metadata.get('id')) is not int or metadata.get('id') != repository_id or str(metadata.get('full_name','')).lower() != full_name.lower():
            raise SourceError('GITHUB_REPOSITORY_IDENTITY_MISMATCH')
        return self.content(full_name,path,analysis['base_sha'],token), self.content(full_name,path,analysis['head_sha'],token)
