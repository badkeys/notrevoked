# SPDX-License-Identifier: 0BSD
# (c) Hanno Böck

import os
import pathlib
import unittest

import notrevoked

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestExpired(unittest.TestCase):

    def test_expired(self):
        for crtfile in ["expired-crl.crt", "expired-ocsp.crt"]:
            crtfp = os.path.join(TDPATH, crtfile)
            crt = pathlib.Path(crtfp).read_bytes()
            ret = notrevoked.notrevoked(crt)
            self.assertEqual(ret, "expired")


if __name__ == "__main__":
    unittest.main()
