#!/usr/bin/env python

import os
import shutil
import tempfile
import logging

try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

import gpgme


log = logging.getLogger()

keydir = os.path.join(os.path.dirname(__file__), 'keys')
test_fpr = '140162A978431A0258B3EC24E69EEE14181523F4'


_gpghome = tempfile.mkdtemp(prefix='tmp.gpghome')

def set_up_temp_dir():
    os.environ['GNUPGHOME'] = _gpghome
    # Copy secrets from .gnupg to temporary dir
    try:
        from_ = os.environ['HOME'] + '/.gnupg/gpg.conf'
        to_ = _gpghome
        shutil.copy(from_, to_)
        log.debug('copied your gpg.conf from %s to %s', from_, to_)
    except IOError as e:
        log.error('User has no gpg.conf file')

def remove_temp_dir():
    del os.environ['GNUPGHOME']
    shutil.rmtree(_gpghome, ignore_errors=True)


def keyfile(key):
    return open(os.path.join(keydir, key), 'rb')


def import_data(context, keydata):
    result = context.import_(keydata)
    return result


def export_key(context, fpr, armor=True):
    context.armor = armor
    keydata = BytesIO()
    context.export(fpr, keydata)
    return keydata


def main():
    # set up the environment
    set_up_temp_dir()
    ctx = gpgme.Context()

    # test key import
    with keyfile('key1.pub') as fp:
        result = import_data(ctx, fp)
    assert result.imports[0] == (test_fpr, None, gpgme.IMPORT_NEW), "Fail on import"

    # test key export
    keydata = export_key(ctx, result.imports[0][0])
    assert keydata.getvalue().startswith(
            b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n'), "Fail on export"

    # clean testing environment
    remove_temp_dir()

if __name__ == '__main__':
    main()