#!/usr/bin/env python

import logging
from string import Template

import os
import shutil
import tempfile
from tempfile import NamedTemporaryFile
from distutils.spawn import find_executable

from monkeysign.gpg import Keyring, TempKeyring
import gpgme
from io import BytesIO
from StringIO import StringIO


log = logging.getLogger()

orig_gpghome = os.environ['HOME'] + '/.gnupg/'
_gpghome = tempfile.mkdtemp(prefix='tmp.gpghome')

def set_up_temp_dir():
    """Sets up a temporary directory as gnupg home
    """
    os.environ['GNUPGHOME'] = _gpghome


def remove_temp_dir():
    """Removes the directory for gnugp home
    """
    try:
        del os.environ['GNUPGHOME']
    except KeyError as err:
        log.error("'GNUPGHOME key not set.'")
        return
    shutil.rmtree(_gpghome, ignore_errors=True)


def copy_secrets(gpgmeContext):
    """Copies secrets from .gnupg to temporary dir
    """
    try:
        from_ = orig_gpghome + 'gpg.conf'
        to_ = _gpghome
        shutil.copy(from_, to_)
        log.debug('copied your gpg.conf from %s to %s', from_, to_)
    except IOError as e:
        log.error('User has no gpg.conf file')

    # Copy the public parts of the secret keys to the tmpkeyring
    secret_keys = [key for key in gpgmeContext.keylist(None, True)]

    gpgtemp = _gpghome
    for key in secret_keys:
        if not key.revoked and not key.expired and not key.invalid and not key.subkeys[0].disabled:
            import_key_to_tmpdir(gpgmeContext, key.subkeys[0].fpr, gpgtemp)


def import_key_to_tmpdir(gpgmeContext, fpr, new_homedir):
    """Imports a key into a temporary keyring.

    It uses Context.set_engine_info() to restrict the change of gpg
    directory to current context, elsewhere it would change it globally
    through os.environ['GNUPGHOME']
    """
    gpg_path = find_executable('gpg')

    # The default context has access to user's default keyring
    ctx = gpgme.Context()
    keydata = extract_keydata(ctx, fpr, True)
    # It seems that keys can be imported from string streams only
    keydataIO = StringIO(keydata)

    gpgmeContext.set_engine_info(gpgme.PROTOCOL_OpenPGP, gpg_path, gpghome)
    res = gpgmeContext.import_(keydataIO)

    return len(res.imports) != 0


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
    keydata = BytesIO()
    gpgmeContext.export(fpr, keydata)
    return keydata.getvalue()


def UIDExport_gpgme(uid, keydata):
    set_up_temp_dir()

    ctx = gpgme.Context()
    # XXX: do we need to set a "always-trust" flag ?
    data = BytesIO(keydata)
    try:
        result = ctx.import_(data)
    except gpgme.GpgmeError as err:
        log.error("Couldn't import the key with the following keydata:\n%s", keydata)
        raise ValueError('Invalid keydata')

    keys = [key for key in ctx.keylist(uid)]
    for key in keys:
        for u in key.uids:
            # XXX: at this moment I don't know a way to delete other UIDs from the key
            # so in the end we have only the uid that must be signed
            if u != uid:
                log.info('Deleting UID %s from key %s', u.uid, key.subkeys[0].fpr)
                try:
                    key.uids.remove(u)
                except ValueError as err:
                    log.error("Couldn't delete UID %s from key %s", u.uid, key.subkeys[0].fpr)

    keydata = BytesIO()
    ctx.export(uid, keydata)

    remove_temp_dir()
    return keydata.getvalue()

class KeyringGPG:
    """A class that has the functionalities of a keyring

    It aggregates a gpgme.Context object through which executes gpg calls.
    Aggregation is used because normal inheritance isn't possible.
    """

    default_gpghome = os.environ['HOME'] + '/.gnupg/'

    def __init__(self, tmphome = True):
        self.log = logging.getLogger()
        self._gpghome = None

        if tmphome:
            self._gpghome = tempfile.mkdtemp(prefix='tmp.gpghome')
            self.set_up_tmp_dir()

        self.ctx = gpgme.Context()


    def __del__(self):
        if self._gpghome and not self._gpghome.startswith(default_gpghome):
            del os.environ['GNUPGHOME']
            shutil.rmtree(self._gpghome, ignore_errors=True)


    def set_up_tmp_dir(self):
        os.environ['GNUPGHOME'] = self._gpghome
        # Copy secrets from .gnupg to temporary dir
        try:
            from_ = os.environ['HOME'] + '/.gnupg/gpg.conf'
            to_ = self._gpghome
            shutil.copy(from_, to_)
            self.log.debug('copied your gpg.conf from %s to %s', from_, to_)
        except IOError as e:
            self.log.error('User has no gpg.conf file')


    def import_data(self, keydata):
        data = BytesIO(keydata)
        try:
            result = self.ctx.import_(data)
        except gpgme.GpgmeError as err:
            self.log.error("Couldn't import the key with the following keydata:\n%s", keydata)
            return False
        # XXX: we stick to return True/False for compatibility issues.
        # The gpgme.ImportResult can be used to extract more information.
        return True


    def export_data(self, fpr, armor = True):
        self.ctx.armor = armor
        keydata = BytesIO()
        self.ctx.export(fpr, keydata)

        return keydata.getvalue()


    def get_key(self, fpr):
        key = None
        try:
            key = self.ctx.get_key(fpr)
        except gpgme.GpgmeError as err:
            self.log.error('No key found with fpr %s', fpr)
            raise ValueError('Invalid fingerprint')

        return key


    def get_keylist(self, keyid = None, secret = False):
        keys = [key for key in context.keylist(keyid, secret)]
        return keys



### From Sections.py ###

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



### Below functions represent gpg calls that mostly depend on
### monkeysign.gpg.Keyring and monkeysign.gpg.Context classes

def keyring_set_option(keyring, option, value = None):
    try:
        if option in keyring.context.options:
            keyring.context.set_option(option, value)

    except AttributeError:
        log.error("Object %s has no attribute context", keyring)
    except TypeError:
        log.error("Object %s is not a Keyring type", keyring)


def keyring_call_command(keyring, command, stdin = None):
    try:
        if option in keyring.context.options:
            keyring.context.call_command(command, stdin)

    except AttributeError:
        log.error("Object %s has no attribute context", keyring)
    except TypeError:
        log.error("Object %s is not a Keyring type", keyring)


def keyring_import_data(keyring, data):
    if keyring.import_data(data):
        imported_key_fpr = keyring.get_keys().keys()[0]
        log.debug("Imported data with fpr:\n%s", imported_key_fpr)

    else:
        log.error("Couldn't import data:\n%s", data)


def keyring_export_data(keyring, keyid):
    keys = keyring.get_keys(keyid)
    key = keys.values()[0]

    keyring.export_data(key.fpr, secret=False)
    keydata = keyring.context.stdout
    return keydata


def keyring_get_keys(keyring, keyid=None):
    keys_dict = keyring.get_keys(keyid)
    return keys_dict



if __name__ == '__main__':
    keyring = GetNewKeyring()
    print keyring.get_keys()