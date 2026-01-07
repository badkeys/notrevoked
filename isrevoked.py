#!/usr/bin/python3

import argparse
import datetime
import functools
import os
import pathlib
import urllib.request

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID


@functools.cache
def _cachedir():
    cachehome = os.getenv("XDG_CACHE_HOME")
    if cachehome:
        cachedir = os.path.join(cachehome, "isrevoked", "")
    else:
        cachedir = os.path.expanduser("~/.cache/isrevoked/")
    if not os.path.isdir(cachedir):
        os.mkdir(cachedir)
    return cachedir


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
    cachefn = crlurl.split("//")[-1].replace("/", "_")
    cachefp = os.path.join(_cachedir(), cachefn)

    crl = None
    if os.path.isfile(cachefp):
        cachetime = int(os.path.getmtime(cachefp))
        now = datetime.datetime.now(tz=datetime.UTC)
        # always remove cache files older than 10 days
        if (int(now.timestamp()) - cachetime) > 10 * 24 * 60 * 60:
            os.remove(cachefp)
        crl_raw = pathlib.Path(cachefp).read_bytes()
        crl = x509.load_der_x509_crl(crl_raw)

        if crl.next_update_utc < now:
            os.remove(cachefp)
            crl = None

    if not crl:
        with urllib.request.urlopen(crlurl) as u:
            crl_raw = u.read()
            pathlib.Path(cachefp).write_bytes(crl_raw)
        crl = x509.load_der_x509_crl(crl_raw)

    if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
        return "revoked"
    return "valid"


def isrevoked(pem):
    cert = x509.load_pem_x509_certificate(pem)

    if cert.not_valid_after_utc < datetime.datetime.now(tz=datetime.UTC):
        return "expired"

    _, _, crl = geturls(cert)

    if crl:
        return checkcrl(cert, crl)

    return "unknown"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("certificate", nargs="+")
    args = ap.parse_args()

    ret = 0
    for certfile in args.certificate:
        pem = pathlib.Path(certfile).read_bytes()
        rev = isrevoked(pem)
        print(f"{certfile}: {rev}")
