#!/usr/bin/env python

# FIXME:
# Extract all cases where gpg support comes from monkeysign and
# add them to this file.

import logging
from string import Template

import os
import shutil
import tempfile
from tempfile import NamedTemporaryFile

from monkeysign.gpg import Keyring, TempKeyring

SUBJECT = 'Your signed key $fingerprint'
BODY = '''Hi $uid,


I have just signed your key

      $fingerprint


Thanks for letting me sign your key!

--
GNOME Keys
'''

log = logging.getLogger()
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


def use_case_import_data(keyring, data):
    if keyring.import_data(data):
        imported_key_fpr = keyring.get_keys().keys()[0]
        print imported_key_fpr

    else:
        print "Failed to import data"


def use_case_export_data(keyring, keyid):
    # keyring is a monkeysign.gpg.Keyring object
    keys = keyring.get_keys(keyid)
    key = keys.values()[0]

    # key is a monkeysign.gpg.OpenPGPkey object
    keyid = key.keyid()
    fpr = key.fpr

    keyring.export_data(fpr, secret=False)
    keydata = keyring.context.stdout


def use_case_sign_key(keyring, data, fingerprint):
    keyring.context.set_option('export-options', 'export-minimal')

    tmpkeyring = TempKeyringCopy(keyring)
    keydata = data

    if keydata:
        stripped_key = MinimalExport(keydata)
    else:
        log.debug("looking for key %s in your keyring", fingerprint)
        keyring.context.set_option('export-options', 'export-minimal')
        stripped_key = keyring.export_data(fingerprint)

    log.debug('Trying to import key\n%s', stripped_key)

    if tmpkeyring.import_data(stripped_key):
        keys = tmpkeyring.get_keys(fingerprint)
        log.info("Found keys %s for fp %s", keys, fingerprint)
        assert len(keys) == 1, "We received multiple keys for fp %s: %s" % (fingerprint, keys)
        key = keys[fingerprint]
        uidlist = key.uidslist

        # FIXME: For now, we sign all UIDs. This is bad.
        ret = tmpkeyring.sign_key(uidlist[0].uid, signall=True)
        log.info("Result of signing %s on key %s: %s", uidlist[0].uid, fingerprint, ret)

        for uid in uidlist:
            uid_str = uid.uid
            log.info("Processing uid %s %s", uid, uid_str)

            # 3.2. export and encrypt the signature
            # 3.3. mail the key to the user
            signed_key = UIDExport(uid_str, tmpkeyring.export_data(uid_str))
            log.info("Exported %d bytes of signed key", len(signed_key))
            # self.signui.tmpkeyring.context.set_option('armor')
            tmpkeyring.context.set_option('always-trust')
            encrypted_key = tmpkeyring.encrypt_data(data=signed_key, recipient=uid_str)

            keyid = str(key.keyid())
            ctx = {
                'uid' : uid_str,
                'fingerprint': fingerprint,
                'keyid': keyid,
            }
            # We could try to dir=tmpkeyring.dir
            # We do not use the with ... as construct as the
            # tempfile might be deleted before the MUA had the chance
            # to get hold of it.
            # Hence we reference the tmpfile and hope that it will be properly
            # cleaned up when this object will be destroyed...
            tmpfile = NamedTemporaryFile(prefix='gnome-keysign-', suffix='.asc')
            self.tmpfiles.append(tmpfile)
            filename = tmpfile.name
            log.info('Writing keydata to %s', filename)
            tmpfile.write(encrypted_key)
            # Interesting, sometimes it would not write the whole thing out,
            # so we better flush here
            tmpfile.flush()
            # As we're done with the file, we close it.
            #tmpfile.close()

            subject = Template(SUBJECT).safe_substitute(ctx)
            body = Template(BODY).safe_substitute(ctx)
            self.email_file (to=uid_str, subject=subject,
                             body=body, files=[filename])


def use_case_main():
    # These are a couple of use case scenarios for monkeysign' gpg wrapper
    # that we need to redo using pygpgme

    keyid = '181523F4'
    keydata = 'Example data'
    fingerprint = '140162A978431A0258B3EC24E69EEE14181523F4'

    keyring = Keyring()
    tempkeyring = TempKeyringCopy(keyring)

    use_case_import_data(tempkeyring, keydata)
    use_case_export_data(tempkeyring, keyid)
    use_case_sign_key(tempkeyring, keydata, fingerprint)


##############################################################################
### This part is where we are replacing the above calls to monkeysign API with
### gpgme calls
##############################################################################

import gpgme
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO


keydir = os.path.join(os.path.dirname(__file__), 'keys')
test_fpr = '140162A978431A0258B3EC24E69EEE14181523F4'


_gpghome = tempfile.mkdtemp(prefix='tmp.gpghome')
gpg_conf_contents = ''

ctx = gpgme.Context()

def set_up():
    os.environ['GNUPGHOME'] = _gpghome
    fd = open(os.path.join(_gpghome, 'gpg.conf'), 'wb')
    fd.write(gpg_conf_contents.encode('UTF-8'))
    fd.close()


def tear_down():
    del os.environ['GNUPGHOME']
    shutil.rmtree(_gpghome, ignore_errors=True)


def keyfile(key):
    return open(os.path.join(keydir, key), 'rb')


def import_data(keydata):
    result = ctx.import_(keydata)
    return result


def export_key(fpr, armor=True):
    ctx.armor = armor
    keydata = BytesIO()
    ctx.export(fpr, keydata)
    return keydata


def main():
    # set up the environment
    set_up()

    # test import
    with keyfile('key1.pub') as fp:
        result = import_data(fp)
    assert result.imports[0] == (test_fpr, None, gpgme.IMPORT_NEW), "Fail on import"

    # test export
    keydata = export_key(result.imports[0][0])
    assert keydata.getvalue().startswith(
            b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n'), "Fail on export"

    # clean testing environment
    tear_down()

if __name__ == '__main__':
    main()