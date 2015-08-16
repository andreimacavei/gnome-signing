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
import shutil
import tempfile
from distutils.spawn import find_executable

import gpgme
import gpgme.editutil
from io import BytesIO
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


log = logging.getLogger(__name__)

gpg_default = os.environ.get('GNUPGHOME', os.environ['HOME'] + '/.gnupg/')
gpg_path = find_executable('gpg')


def gpg_set_engine(gpgmeContext, protocol=gpgme.PROTOCOL_OpenPGP, dir_prefix=None):
    """Sets up a temporary directory as new gnupg home
    for this context
    """
    dir_prefix = dir_prefix if dir_prefix else 'tmp.gpghome'
    temp_dir = tempfile.mkdtemp(prefix=dir_prefix)
    gpgmeContext.set_engine_info(protocol, gpg_path, temp_dir)
    return temp_dir


def gpg_reset_engine(gpgmeContext, tmp_dir=None, protocol=gpgme.PROTOCOL_OpenPGP):
    """Resets the gnupg dir to its default location
    for current context
    """
    gpgmeContext.set_engine_info(protocol, gpg_path, gpg_default)
    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def gpg_copy_secrets(gpgmeContext, gpg_homedir):
    """Copies secrets from .gnupg to new @gpg_homedir
    """
    ctx = gpgme.Context()

    secring_path = gpg_default + 'secring.gpg'
    shutil.copy(secring_path, gpg_homedir)
    log.debug('copied your secring.gpg from %s to %s', secring_path, gpg_homedir)

    try:
        conf_path = gpg_default + 'gpg.conf'
        shutil.copy(conf_path, gpg_homedir)
        log.debug('copied your gpg.conf from %s to %s', conf_path, gpg_homedir)
    except IOError as e:
        log.error('User has no gpg.conf file')

    # Imports user's private keys into the new keyring
    secret_keys = [key for key in ctx.keylist(None, True)]
    # We set again the gpg homedir because there is no contex method "get_engine_info"
    # to tell us what gpg home it uses.
    gpgmeContext.set_engine_info(gpgme.PROTOCOL_OpenPGP, gpg_path, gpg_homedir)

    for key in secret_keys:
        if not key.revoked and not key.expired and not key.invalid and not key.subkeys[0].disabled:
            gpg_import_key(gpgmeContext, key.subkeys[0].fpr)


def gpg_import_key(gpgmeContext, fpr):
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


def gpg_import_keydata(gpgmeContext, keydata):
    """Tries to import a OpenPGP key from @keydata

    The @gpgmeContext object has a gpg directory already set.
    """
    # XXX: PyGPGME key imports doesn't work with data as unicode strings
    # but here we get data coming from network which is unicode
    keydata = keydata.encode('utf-8')
    keydataIO = BytesIO(keydata)
    try:
        result = gpgmeContext.import_(keydataIO)
    except gpgme.GpgmeError as err:
        log.error("Couldn't import the key with the following keydata:\n%s", keydataIO.getvalue())
        return False
    # XXX: we stick to return True/False for compatibility issues.
    # The gpgme.ImportResult can be used to extract more information.
    return True


def gpg_get_keylist(gpgmeContext, keyid=None, secret=False):
    """Returns the keys found in @gpgmeContext
    If @keyid is None then all geys will be returned.
    If @secret=True then it will return the secret keys.
    """
    keys = [key for key in gpgmeContext.keylist(keyid, secret)]
    return keys


def gpg_get_siglist(gpgmeContext, keyid):
    '''Returns a list with all signatures for this @keyid
    '''
    siglist = set()
    gpgmeContext.keylist_mode = gpgme.KEYLIST_MODE_SIGS
    key = gpgmeContext.get_key(keyid)

    for uid in key.uids:
        sigs = [sig for sig in uid.signatures]
        siglist = siglist.union(sigs)

    return list(siglist)


def gpg_sign_uid(gpgmeContext, gpg_homedir, userId):
    """Signs a specific uid of a OpenPGP key

    @gpg_homedir is the directory that @gpgmeContext uses for gpg.
    @userId is a gpgme.UserId object
    """
    # we import the user's primary key that will be used to sign
    gpg_copy_secrets(gpgmeContext, gpg_homedir)
    primary_key = [key for key in gpgmeContext.keylist(None, True)][0]
    gpgmeContext.signers = [primary_key]

    try:
        uid_name, uid_email, uid_comment = userId.name, userId.email, userId.comment
    except AttributeError as exp:
        msg = "Invalid UserId object: %r" % userId
        log.error(msg)
        raise ValueError(msg)

    # we set keylist mode so we can see signatures
    gpgmeContext.keylist_mode = gpgme.KEYLIST_MODE_SIGS
    key = gpgmeContext.get_key(userId.uid)

    i = 1
    # check if we didn't already signed this uid of the key
    for uid in key.uids:
        sigs = [sig for sig in uid.signatures if primary_key.subkeys[0].fpr.endswith(sig.keyid)]

        # check if this uid is the same with the one that we want to sign
        if (uid.name.startswith(uid_name) and uid.email.startswith(uid_email)
                    and uid.comment.startswith(uid_comment)):

            if len(sigs) == 0:
                gpgme.editutil.edit_sign(gpgmeContext, key, index=i, check=0)

            else:
                # we already signed this UID
                log.info("Uid %s was already signed by key: \n%s", userId.uid, key.subkeys[0].fpr)
                return False
            break
        i += 1

    return True


def gpg_encrypt_data(gpgmeContext, data, uid, armor=True):
    """Encrypts @data for the recipients @uid
    """
    plaintext = BytesIO(data)
    ciphertext = BytesIO()
    gpgmeContext.armor = armor
    recipients = gpg_get_keylist(gpgmeContext, uid)

    gpgmeContext.encrypt(recipients, gpgme.ENCRYPT_ALWAYS_TRUST,
                        plaintext, ciphertext)
    return ciphertext.getvalue()


def extract_fpr(gpgmeContext, keyid):
    """Extracts the fingerprint of a key with @keyid.
    """
    try:
        key = gpgmeContext.get_key(keyid)
    except gpgme.GpgmeError as err:
        log.error('No key found with id: %s', keyid)
        raise ValueError("Invalid keyid")

    # A gpgme.Key object doesn't have a fpr but a gpgme.Subkey does
    return key.subkeys[0].fpr


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


def gpg_format_key(gpgmeKey):
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
