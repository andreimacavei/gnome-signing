#!/usr/bin/env python
#    Copyright 2015 Andrei Macavei <andrei.macavei89@gmail.com>
#
#    This file is part of GNOME Keysign.
#
#    GNOME Keysign is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    GNOME Keysign is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with GNOME Keysign.  If not, see <http://www.gnu.org/licenses/>.

import os
from os.path import expanduser
import sys
import shutil
import tempfile

import gpgme
import gpg

import unittest

from io import BytesIO, StringIO

__all__ = ['GpgTestSuite']

keydir = os.path.join(os.path.dirname(__file__), 'keys')
gpg_default = os.environ.get('GNUPGHOME', os.path.join(expanduser("~"), '.gnupg'))


class GpgTestSuite(unittest.TestCase):

    def keyfile(self, key):
        return open(os.path.join(keydir, key), 'rb')

    def test_gpg_set_engine(self):
        ctx = gpgme.Context()

        tmpdir = tempfile.mkdtemp(prefix='tmp.gpghome')
        gpg.gpg_set_engine(ctx, gpgme.PROTOCOL_OpenPGP, tmpdir)

        keys = [key for key in ctx.keylist()]

        self.assertEqual(len(keys), 0)
        self.assertEqual(ctx.protocol, gpgme.PROTOCOL_OpenPGP)

        # clean temporary dir
        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_gpg_reset_engine(self):
        ctx = gpgme.Context()
        # set a temporary dir for gpg home
        tmpdir = tempfile.mkdtemp(prefix='tmp.gpghome')
        ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, None, tmpdir)

        # check if we have created the new gpg dir
        self.assertTrue(os.path.isdir(tmpdir))
        gpg.gpg_reset_engine(ctx, tmpdir, gpgme.PROTOCOL_OpenPGP)

        self.assertEqual(gpgme.PROTOCOL_OpenPGP, ctx.protocol)
        self.assertFalse(os.path.exists(tmpdir))

        # clean temporary dir
        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_gpg_import_private_key(self):
        ctx = gpgme.Context()
        tmpdir = tempfile.mkdtemp(prefix='tmp.gpghome')
        ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, None, tmpdir)

        gpg.gpg_import_private_key(ctx)

        # get the user's secret keys
        default_ctx = gpgme.Context()
        default_ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, None, gpg_default)
        default_secret_keys = [key for key in default_ctx.keylist(None, True)]

        # compare the imported keys with the original secret keys
        secret_keys = [key for key in ctx.keylist(None, True)]

        self.assertEqual(len(secret_keys), len(default_secret_keys))
        all_keys = sum(key1.subkeys[0].fpr != key2.subkeys[0].fpr for key1, key2 in zip(secret_keys, default_secret_keys))
        self.assertFalse(all_keys)

        # clean temporary dir
        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_gpg_import_keydata(self):
        ctx = gpgme.Context()
        tmpdir = tempfile.mkdtemp(prefix='tmp.gpghome')
        ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, None, tmpdir)

        with self.keyfile('testkey1.pub') as fp:
            keydata = fp.read()

        res = gpg.gpg_import_keydata(ctx, keydata)
        self.assertTrue(res)

        # can we get the key ?
        key = ctx.get_key('john.doe@test.com')

    def test_gpg_sign_uid(self):
        ctx = gpgme.Context()
        tmpdir = tempfile.mkdtemp(prefix='tmp.gpghome')
        ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, None, tmpdir)

        with self.keyfile('testkey1.pub') as fp:
            ctx.import_(fp)

        with self.keyfile('signonly.sec') as fp:
            secret_key = fp.read()

        userId = ctx.get_key('john.doe@test.com').uids[0]
        res = gpg.gpg_sign_uid(ctx, tmpdir, userId, secret_key)

        self.assertTrue(res)

        # verify if we have the uid signed
        sigs = ctx.get_key('john.doe@test.com').uids[0].signatures
        self.assertEqual(len(sigs), 2) #we're counting the self signature


if __name__ == '__main__':
    unittest.main()