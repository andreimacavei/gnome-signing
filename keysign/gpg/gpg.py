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


import logging
from string import Template

import os
import sys
import shutil
import tempfile
import subprocess

import gpgme
import gpgme.editutil
from io import BytesIO
from datetime import datetime
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


log = logging.getLogger(__name__)

def set_engine(gpgmeContext, protocol=gpgme.PROTOCOL_OpenPGP, dir_prefix=None):
    """Sets up a temporary directory as new gnupg home
    for this context
    """
    dir_prefix = dir_prefix if dir_prefix else 'tmp.gpghome'
    temp_dir = tempfile.mkdtemp(prefix=dir_prefix)
    gpgmeContext.set_engine_info(protocol, None, temp_dir)
    return temp_dir


def reset_engine(gpgmeContext, tmp_dir=None, protocol=gpgme.PROTOCOL_OpenPGP):
    """Resets the gnupg homedir for the received context
    """
    gpgmeContext.set_engine_info(protocol, None, None)
    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def import_private_key(gpgmeContext, secret_key=None):
    """Imports the user's private key from @secret_key or the default keyring
     to a temporary context.
    """
    if secret_key:
        keydata = secret_key
    else:
        # XXX: There is no option to export a private key in GPGME. Latest post about it can
        # be found here: https://lists.gnupg.org/pipermail/gnupg-devel/2015-August/030229.html
        # We use this hack for now to import user's private key into a temp keyring
        keydata = subprocess.check_output(["gpg", "--armor", "--export-secret-keys"])

    with BytesIO(keydata) as fp:
        gpgmeContext.import_(fp)

    # Import the personal public keys also
    ctx = gpgme.Context()
    keys = [key for key in ctx.keylist(None, True)]

    for key in keys:
        if not key.revoked and not key.expired and not key.invalid and not key.subkeys[0].disabled:
            import_key(gpgmeContext, key.subkeys[0].fpr)
            log.debug("imported your personal key: %s to tmp keyring", key.subkeys[0].fpr)



def import_key(gpgmeContext, fpr):
    """Imports a key from the user's keyring into the keyring received
    as argument.

    It assumes that the received keyring (@gpgmeContext) has its gpg homedir set already.
    """
    # Get the default keyring
    ctx = gpgme.Context()
    keydata = BytesIO()
    ctx.export(fpr, keydata)

    if not keydata.getvalue():
        log.error("No key found in user's keyring with fpr:\n%s", fpr)
        raise ValueError('Invalid fingerprint')

    keydata.seek(0)
    res = gpgmeContext.import_(keydata)
    return len(res.imports) != 0


def import_keydata(gpgmeContext, keydata):
    """Tries to import a OpenPGP key from @keydata.
    Keydata needs to be bytes (or an encoded string).

    The @gpgmeContext object has a gpg directory already set.
    """
    keydataIO = BytesIO(keydata)
    result = None
    try:
        result = gpgmeContext.import_(keydataIO)
    except gpgme.GpgmeError as err:
        log.error("Couldn't import the key with the following keydata:\n%s", keydataIO.getvalue())
    return result


def get_keylist(gpgmeContext, keyid=None, secret=False, expired=False):
    """Returns the keys found in @gpgmeContext

    @keyid: the unique id of a key.
    @secret: if set to True it returns the secret keys, else it returns the public keys.
    @expired: if set to True it also returns the expired keys.
    """
    keys = []
    for key in gpgmeContext.keylist(keyid, secret):
        exp_date = datetime.fromtimestamp(float(key.subkeys[0].expires))
        if expired == False and key.subkeys[0].expires != 0 and exp_date.date() < datetime.today().date():
            continue
        keys.append(key)

    return keys


def get_siglist(gpgmeContext, keyid):
    '''Returns a list with all signatures for this @keyid
    '''
    siglist = set()
    gpgmeContext.keylist_mode = gpgme.KEYLIST_MODE_SIGS
    key = gpgmeContext.get_key(keyid)

    for uid in key.uids:
        sigs = [sig for sig in uid.signatures]
        siglist = siglist.union(sigs)

    return list(siglist)


def sign_uid(gpgmeContext, gpg_homedir, userId, secret_key=None):
    """Signs a specific uid of a OpenPGP key

    gpgmeContext: the temporary keyring
    gpg_homedir: the current GPG directory
    userId: sign this userId
    secret_key: if this is given than it will be used as the primary key

    @rtype: bool
    @return: True/False depending if this uid was signed for the first time
    by this key
    """
    import_private_key(gpgmeContext, secret_key)

    primary_key = [key for key in gpgmeContext.keylist(None, True)][0]
    gpgmeContext.signers = [primary_key]

    try:
        uid_name, uid_email, uid_comment = userId.name, userId.email, userId.comment
    except AttributeError as exp:
        msg = "Invalid UserId object: %r" % userId
        log.error(msg)
        raise ValueError(msg)

    # We set keylist mode so we can see signatures
    gpgmeContext.keylist_mode = gpgme.KEYLIST_MODE_SIGS
    key = gpgmeContext.get_key(userId.uid)

    first_sig = True

    for (i, uid) in enumerate(key.uids):
        # Check if this uid is the same with the one that we want to sign
        if uid.name == uid_name and uid.email == uid_email and uid.comment == uid_comment:

            sigs = [sig for sig in uid.signatures if primary_key.subkeys[0].fpr.endswith(sig.keyid)]
            if not len(sigs) == 0:
                # This uid was signed by this key in the past. Update signature but set 'first_sig' to False
                first_sig = False

            gpgme.editutil.edit_sign(gpgmeContext, key, index=i, check=0)
            break

    return first_sig


def encrypt_data(gpgmeContext, data, uid, armor=True):
    """Encrypts @data for the recipients @uid
    """
    plaintext = BytesIO(data)
    ciphertext = BytesIO()
    gpgmeContext.armor = armor
    recipients = get_keylist(gpgmeContext, uid)

    gpgmeContext.encrypt(recipients, gpgme.ENCRYPT_ALWAYS_TRUST,
                        plaintext, ciphertext)
    return ciphertext.getvalue()


def export_key(gpgmeContext, fpr, armor=False, mode=None):
    """Exports the key with the given fingerprint from the user's keyring.

    The key can be exported in ASCII-armored format if armor is set.
    """
    gpgmeContext.armor = armor
    keydata = BytesIO()
    if mode:
        gpgmeContext.export(fpr, keydata, mode)
    else:
        gpgmeContext.export(fpr, keydata)
    return keydata.getvalue()


def format_fpr(fpr):
    """display a clean version of the fingerprint

    this is the display we usually see
    """
    l = list(fpr) # explode
    s = ''
    for i in range(10):
        # output 4 chars
        s += ''.join(l[4*i:4*i+4])
        # add a space, except at the end
        if i < 9: s += ' '
        # add an extra space in the middle
        if i == 4: s += ' '
    return s


def format_key(gpgmeKey):
    """Returns a string representation of @gpgmeKey

    It contains info about: length of key, keyid, expiration date, creation date,
    fingerprint, uids and subkeys.
    """
    subkey = gpgmeKey.subkeys[0]

    ret = u'pub  %sR/%s' % (subkey.length, subkey.fpr[-8:])
    ret += u' %s' % (subkey.timestamp, )
    if subkey.expires: ret += u' [expires: %s]' % (subkey.expires,)
    ret += '\n'
    ret += u'    Fingerprint = %s\n' % (format_fpr(subkey.fpr),)
    i = 1
    for uid in gpgmeKey.uids:
        ret += u"uid %d      %s\n" % (i, uid.uid.decode('utf8'))
        i += 1
    for sk in gpgmeKey.subkeys:
        if not sk.fpr.startswith(subkey.fpr):
            ret += u"sub   %sR/%s %s" % (sk.length, sk.fpr[-8:], sk.timestamp)
            if sk.expires: ret += u' [expires: %s]\n' % (sk.expires,)
    return ret
