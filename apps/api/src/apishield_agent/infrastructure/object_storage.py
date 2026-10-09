"""Private bounded S3 objects, keyed by product, tenant, artifact and SHA-256.

Content-addressed keys bind generations to bytes. Credentials never leave the server.
"""
import hashlib
import hmac
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from uuid import UUID
from fastapi import HTTPException


def reject(code, status=409):
    raise HTTPException(status, {"type":"about:blank", "title":"Artifact storage rejected", "status":status, "code":code, "detail":"Artifact storage is unavailable or object integrity verification failed", "request_id":"runtime"})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ObjectStorage:
    def __init__(self, product, max_bytes=1048576):
        self.product=product; self.max_bytes=max_bytes
        self.endpoint=os.environ.get("S3_ENDPOINT", "").rstrip("/")
        self.bucket=os.environ.get("S3_BUCKET", "")
        self.region=os.environ.get("S3_REGION", "auto")
        self.access=os.environ.get("S3_ACCESS_KEY_ID", "")
        self.secret=os.environ.get("S3_SECRET_ACCESS_KEY", "")
        self.style=os.environ.get("S3_URL_STYLE", "virtual-host")
        parsed=urllib.parse.urlsplit(self.endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or parsed.port:
            reject("STORAGE_NOT_CONFIGURED",503)
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",self.bucket) or not self.access or not self.secret or self.style not in {"path","virtual-host"}:
            reject("STORAGE_NOT_CONFIGURED",503)
        if not re.fullmatch(r"[a-z0-9-]+",product) or not re.fullmatch(r"[a-z0-9-]+",self.region):
            reject("STORAGE_NOT_CONFIGURED",503)
        self.host=parsed.hostname
        self.opener=urllib.request.build_opener(NoRedirect())

    def key(self, tenant, artifact, digest):
        if not re.fullmatch(r"[0-9a-f]{64}",digest):reject("ARTIFACT_DIGEST_MISMATCH")
        return f"{self.product}/{UUID(str(tenant))}/{UUID(str(artifact))}/{digest}"

    def signed_request(self, method, key, body=None, timestamp=None):
        host=self.host if self.style=="path" else self.bucket+"."+self.host
        path="/"+(self.bucket+"/" if self.style=="path" else "")+urllib.parse.quote(key,safe="/-_.~")
        now=timestamp or datetime.now(timezone.utc)
        stamp=now.strftime("%Y%m%dT%H%M%SZ");date=now.strftime("%Y%m%d")
        digest=hashlib.sha256(body or b"").hexdigest()
        headers={"host":host,"x-amz-content-sha256":digest,"x-amz-date":stamp}
        names=";".join(sorted(headers));canonical="".join(k+":"+headers[k]+"\n" for k in sorted(headers))
        request="\n".join([method,path,"",canonical,names,digest])
        scope=f"{date}/{self.region}/s3/aws4_request"
        message="\n".join(["AWS4-HMAC-SHA256",stamp,scope,hashlib.sha256(request.encode()).hexdigest()])
        sign=lambda key,value:hmac.new(key,value.encode(),hashlib.sha256).digest()
        key_sign=sign(sign(sign(sign(("AWS4"+self.secret).encode(),date),self.region),"s3"),"aws4_request")
        signature=hmac.new(key_sign,message.encode(),hashlib.sha256).hexdigest()
        headers["Authorization"]=f"AWS4-HMAC-SHA256 Credential={self.access}/{scope}, SignedHeaders={names}, Signature={signature}"
        return urllib.request.Request("https://"+host+path,data=body,headers=headers,method=method)

    def transfer(self, method, key, body=None):
        try:
            with self.opener.open(self.signed_request(method,key,body),timeout=10) as response:
                result=response.read(self.max_bytes+1)
                if len(result)>self.max_bytes:reject("ARTIFACT_TOO_LARGE",413)
                return result
        except urllib.error.HTTPError as error:
            reject("ARTIFACT_BYTES_MISSING" if error.code==404 else "STORAGE_UNAVAILABLE",409 if error.code==404 else 503)
        except (urllib.error.URLError, TimeoutError, OSError):
            reject("STORAGE_UNAVAILABLE",503)

    def put(self, tenant, artifact, body, digest, size):
        if len(body)>self.max_bytes:reject("ARTIFACT_TOO_LARGE",413)
        if len(body)!=size or hashlib.sha256(body).hexdigest()!=digest:reject("ARTIFACT_DIGEST_MISMATCH")
        key=self.key(tenant,artifact,digest)
        self.transfer("PUT",key,body)
        self.read(tenant,artifact,digest,digest,size)
        return {"generation":digest,"sha256":digest,"size":size}

    def read(self, tenant, artifact, generation, digest, size):
        if generation!=digest:reject("ARTIFACT_GENERATION_MISMATCH")
        if not 1<=size<=self.max_bytes:reject("ARTIFACT_TOO_LARGE",413)
        body=self.transfer("GET",self.key(tenant,artifact,digest))
        if len(body)!=size or hashlib.sha256(body).hexdigest()!=digest:reject("ARTIFACT_INTEGRITY_FAILURE")
        return body
