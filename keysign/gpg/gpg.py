#!/usr/bin/env python

import logging
from string import Template

import os
import shutil
import tempfile
from distutils.spawn import find_executable

from monkeysign.gpg import Keyring, TempKeyring
import gpgme
import gpgme.editutil
from io import BytesIO
from StringIO import StringIO


log = logging.getLogger()

gpg_default = os.environ['HOME'] + '/.gnupg/'
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
            gpg_import_key_by_fpr(gpgmeContext, key.subkeys[0].fpr)


def gpg_import_key_by_fpr(gpgmeContext, fpr):
    """Imports a key received by its @fpr into a temporary keyring.

    It assumes that the received @gpgmeContext has its gpg homedir set already.
    """
    # We make a new context because we need to get the key from it
    ctx = gpgme.Context()
    keydata = extract_keydata(ctx, fpr, True)
    # It seems that keys can be imported from string streams only
    keydataIO = StringIO(keydata)
    try:
        res = gpgmeContext.import_(keydataIO)
    except gpgme.GpgmeError as err:
        log.error("No key found in user's keyring with fpr:\n%s", fpr)
        raise ValueError('Invalid fingerprint')

    return len(res.imports) != 0


def gpg_import_keydata(gpgmeContext, keydata):
    """Tries to import a OpenPGP key from @keydata

    The @gpgmeContext object has a gpg directory already set.
    """
    # XXX: PyGPGME key imports doesn't work with data as unicode strings
    # but here we get data coming from network which is unicode
    keydata = keydata.encode('utf-8')
    keydataIO = StringIO(keydata)
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
        log.error("%s is not a valid gpgme.UserId", userId)
        raise ValueError("Invalid UID")

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


def extract_keydata(gpgmeContext, fpr, armor=False):
    """Extracts key data from a key with fingerprint @fpr.
    Returns the data in plaintext (if armor=True) or binary.
    """
    gpgmeContext.armor = armor
    keydata = StringIO()
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


### Below are functions that use old API and must be replaced ###
def UIDExport(uid, keydata):
    """Export only the UID of a key.
    Unfortunately, GnuPG does not provide smth like
    --export-uid-only in order to obtain a UID and its
    signatures."""
    tmp = TempKeyring()
    # Hm, apparently this needs to be set, otherwise gnupg will issue
    # a stray "gpg: checking the trustdb" which confuses the gnupg library
    tmp.context.set_option('always-trust')
    tmp.import_data(keydata)
    for fpr, key in tmp.get_keys(uid).items():
        for u in key.uidslist:
            key_uid = u.uid
            if key_uid != uid:
                log.info('Deleting UID %s from key %s', key_uid, fpr)
                tmp.del_uid(fingerprint=fpr, pattern=key_uid)
    only_uid = tmp.export_data(uid)

    return only_uid


def MinimalExport(keydata):
    '''Returns the minimised version of a key

    For now, you must provide one key only.'''
    tmpkeyring = TempKeyring()
    ret = tmpkeyring.import_data(keydata)
    log.debug("Returned %s after importing %s", ret, keydata)
    assert ret
    tmpkeyring.context.set_option('export-options', 'export-minimal')
    keys = tmpkeyring.get_keys()
    log.debug("Keys after importing: %s (%s)", keys, keys.items())
    # We assume the keydata to contain one key only
    fingerprint, key = keys.items()[0]
    stripped_key = tmpkeyring.export_data(fingerprint)
    return stripped_key


def GetNewKeyring():
    return Keyring()

def GetNewTempKeyring():
    return TempKeyring()

class TempKeyringCopy(TempKeyring):
    """A temporary keyring which uses the secret keys of a parent keyring

    It mainly copies the public keys from the parent keyring to this temporary
    keyring and sets this keyring up such that it uses the secret keys of the
    parent keyring.
    """
    def __init__(self, keyring, *args, **kwargs):
        self.keyring = keyring
        # Not a new style class...
        if issubclass(self.__class__, object):
            super(TempKeyringCopy, self).__init__(*args, **kwargs)
        else:
            TempKeyring.__init__(self, *args, **kwargs)

        self.log = logging.getLogger()

        tmpkeyring = self
        # Copy and paste job from monkeysign.ui.prepare
        tmpkeyring.context.set_option('secret-keyring', keyring.homedir + '/secring.gpg')

        # copy the gpg.conf from the real keyring
        try:
            from_ = keyring.homedir + '/gpg.conf'
            to_ = tmpkeyring.homedir
            shutil.copy(from_, to_)
            self.log.debug('copied your gpg.conf from %s to %s', from_, to_)
        except IOError as e:
            # no such file or directory is alright: it means the use
            # has no gpg.conf (because we are certain the temp homedir
            # exists at this point)
            if e.errno != 2:
                pass


        # Copy the public parts of the secret keys to the tmpkeyring
        signing_keys = []
        for fpr, key in keyring.get_keys(None, secret=True, public=False).items():
            if not key.invalid and not key.disabled and not key.expired and not key.revoked:
                signing_keys.append(key)
                tmpkeyring.import_data (keyring.export_data (fpr))


## Monkeypatching to get more debug output
import monkeysign.gpg
bc = monkeysign.gpg.Context.build_command
def build_command(*args, **kwargs):
    ret = bc(*args, **kwargs)
    #log.info("Building command %s", ret)
    log.debug("Building cmd: %s", ' '.join(["'%s'" % c for c in ret]))
    return ret
monkeysign.gpg.Context.build_command = build_command



if __name__ == '__main__':
    ctx = gpgme.Context()
    gpghome = gpg_set_engine(ctx)
    gpg_copy_secrets(ctx, gpghome)

    keys = gpg_get_keylist(ctx)
    for key in keys:
        key_str = gpg_format_key(key)
        print ("\nKey: \n%s") %(key_str,)

