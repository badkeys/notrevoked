#!/usr/bin/python3
#
# SPDX-License-Identifier: 0BSD
# (c) Hanno Böck
#
# Part of [badkeys](https://badkeys.info/)

import argparse
import datetime
import functools
import os
import pathlib
import sys
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID


@functools.cache
def _cachedir():
    cachehome = os.getenv("XDG_CACHE_HOME")
    if cachehome:
        cachedir = os.path.join(cachehome, "notrevoked", "")
    else:
        cachedir = os.path.expanduser("~/.cache/notrevoked/")
    if not os.path.isdir(cachedir):
        os.mkdir(cachedir)
    return cachedir


def _warn(msg):
    # prevent control character injection
    fmsg = repr(msg)[1:-1]
    sys.stdout.write(f"WARNING: {fmsg}\n")


def _getfromcache(cachetype, url):
    if cachetype not in ["crl", "issuer"]:
        exmsg = "cachetype must be 'crl' or 'issuer'"
        raise ValueError(exmsg)

    cachefn = url.split("//")[-1].replace("/", "_")
    cachep = os.path.join(_cachedir(), cachetype)
    cachefp = os.path.join(cachep, cachefn)

    havecache = False
    if os.path.isfile(cachefp):
        havecache = True
        if cachetype == "crl":
            cachetime = int(os.path.getmtime(cachefp))
            now = datetime.datetime.now(tz=datetime.UTC)
            # always remove cached CRL files older than 10 days
            if (int(now.timestamp()) - cachetime) > 10 * 24 * 60 * 60:
                os.remove(cachefp)
                havecache = False

    if havecache:
        raw = pathlib.Path(cachefp).read_bytes()
        if cachetype == "crl":
            crl = x509.load_der_x509_crl(raw)
            if crl.next_update_utc < now:
                os.remove(cachefp)
                havecache = False
            else:
                return crl

    if not havecache:
        with urllib.request.urlopen(url) as u:
            raw = u.read()
            mimetype = u.headers.get_content_type()
        if cachetype == "issuer" and mimetype != "application/pkix-cert":
            _warn(f"Wrong content type {mimetype} for CA issuer {url}")
        elif cachetype == "crl" and mimetype != "application/pkix-crl":
            _warn(f"Wrong content type {mimetype} for CRL {url}")

        if not os.path.isdir(cachep):
            os.mkdir(cachep)
        pathlib.Path(cachefp).write_bytes(raw)

    if cachetype == "crl":
        return x509.load_der_x509_crl(raw)
    return x509.load_der_x509_certificate(raw)


def geturls(cert):

    ocsp_url = None
    issuers_url = None
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    except x509.extensions.ExtensionNotFound:
        pass
    else:
        for meth in aia.value:
            if meth.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_url = meth.access_location.value
            if meth.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                issuers_url = meth.access_location.value

    try:
        crlext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        crl_url = crlext.value[0].full_name[0].value
    except x509.extensions.ExtensionNotFound:
        crl_url = None

    return (issuers_url, ocsp_url, crl_url)


def checkcrl(cert, crlurl):
    crl = _getfromcache("crl", crlurl)

    if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
        return "revoked"
    return "valid"


def checkocsp(cert, ocsp_url, issuer_url):
    issuer_cert = _getfromcache("issuer", issuer_url)

    obuilder = ocsp.OCSPRequestBuilder()
    obuilder = obuilder.add_certificate(cert, issuer_cert, hashes.SHA1())  # noqa: DUO134, S303
    req = obuilder.build().public_bytes(serialization.Encoding.DER)

    httpreq = urllib.request.Request(ocsp_url, data=req,
                                     headers={"Content-Type": "application/ocsp-request"})

    with urllib.request.urlopen(httpreq) as ocsphttp:
        ocspresp_raw = ocsphttp.read()
        mimetype = ocsphttp.headers.get_content_type()
    if mimetype != "application/ocsp-response":
        _warn(f"Wrong content type {mimetype} for OCSP Response")

    ocsp_response = ocsp.load_der_ocsp_response(ocspresp_raw)

    if ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD:
        return "valid"
    if ocsp_response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        return "revoked"

    return "error"


def notrevoked(pem):
    cert = x509.load_pem_x509_certificate(pem)

    if cert.not_valid_after_utc < datetime.datetime.now(tz=datetime.UTC):
        return "expired"

    issuer, ocsp, crl = geturls(cert)

    if crl:
        return checkcrl(cert, crl)

    if ocsp:
        return checkocsp(cert, ocsp, issuer)

    return "unknown"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("certificate", nargs="+")
    args = ap.parse_args()

    ret = 0
    for certfile in args.certificate:
        pem = pathlib.Path(certfile).read_bytes()
        rev = notrevoked(pem)
        print(f"{certfile}: {rev}")
