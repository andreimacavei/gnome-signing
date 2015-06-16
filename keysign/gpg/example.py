import gpgme
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

ctx = gpgme.Context()
ctx.armor = True

# key = ctx.get_key('140162A978431A0258B3EC24E69EEE14181523F4')
key = ctx.get_key('85B731F8B58103FD8BDC773AF442F8BBC7336FDB')

plain = BytesIO(b'Hello World\n')
cipher = BytesIO()

ctx.encrypt([key], gpgme.ENCRYPT_ALWAYS_TRUST, plain, cipher)

print(cipher.getvalue())