#!/usr/bin/env python
#

from keysign import __version__ as version

from distutils import cmd
from distutils.command.install_data import install_data as _install_data
from distutils.command.build import build as _build

from setuptools import setup
from setuptools.command.install import install
#import py2exe

from i18n import msgfmt
import os

class build_trans(cmd.Command):
    description = 'Compile .po files into .mo files'
    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        po_dir = os.path.join(os.path.dirname(os.curdir), 'po')
        for path, names, filenames in os.walk(po_dir):
            for f in filenames:
                if f.endswith('.po'):
                    lang = f[:-3]
                    src = os.path.join(path, f)
                    dest_path = os.path.join('build', 'locale', lang, 'LC_MESSAGES')
                    dest = os.path.join(dest_path, 'mussorgsky.mo')
                    if not os.path.exists(dest_path):
                        os.makedirs(dest_path)
                    if not os.path.exists(dest):
                        print 'Compiling %s' % src
                        msgfmt.make(src, dest)
                    else:
                        src_mtime = os.stat(src)[8]
                        dest_mtime = os.stat(dest)[8]
                        if src_mtime > dest_mtime:
                            print 'Compiling %s' % src
                            msgfmt.make(src, dest)

class build(_build):
    sub_commands = _build.sub_commands + [('build_trans', None)]
    def run(self):
        _build.run(self)


class install_data(_install_data):

    def run(self):
        for lang in os.listdir('build/locale/'):
            lang_dir = os.path.join('share', 'locale', lang, 'LC_MESSAGES')
            lang_file = os.path.join('build', 'locale', lang, 'LC_MESSAGES', 'mussorgsky.mo')
            self.data_files.append( (lang_dir, [lang_file]) )
        _install_data.run(self)


setup(
    name = 'gnome-keysign',
    version = version,
    description = 'OpenPGP key signing helper',
    author = 'Tobias Mueller',
    author_email = 'tobiasmue@gnome.org',
    url = 'http://wiki.gnome.org/GnomeKeysign',
    packages = [
        'keysign',
        'keysign.compat',
        'keysign.network',
        'i18n'],
    #package_dir={'keysign': 'keysign'},
    #package_data={'keysign': ['data/']},
    data_files=[
        ('share/applications', ['data/gnome-keysign.desktop']),
        # Hm, hicolor/scalable doesn't seem to work so well
        #('share/icons/hicolor/scalable', ['data/gnome-keysign.svg']),
        ('share/icons', ['data/gnome-keysign.svg']),
    ],
    include_package_data = True,
    #scripts = ['gnome-keysign.py'],
    install_requires=[
        # Note that the dependency on <= 2.2 is only
        # to not confuse Ubuntu 14.04's pip as that
        # seems incompatible with a newer requests library.
        # https://bugs.launchpad.net/ubuntu/+source/python-pip/+bug/1306991
        'requests<=2.2',
        'qrencode',
        #'monkeysign', # Apparently not in the cheeseshop
        # avahi # Also no entry in the cheeseshop
        # dbus # dbus-python is in the cheeseshop but not pip-able
        ],
    license='GPLv3+',
    long_description=open('README.rst').read(),

    entry_points = {
        #'console_scripts': [
        #    'keysign = keysign.main'
        #],
        'gui_scripts': [
            'gnome-keysign = keysign:main',
            'gks-qrcode = keysign.GPGQRCode:main',
        ],
    },
    cmdclass = {
        'build': build,
        'build_trans': build_trans,
        'install_data': install_data,
    },
    classifiers = [
        # Maybe not yet...
        #'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Legal Industry',
        'Intended Audience :: Telecommunications Industry',

        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        # I think we are only 2.7 compatible
        'Programming Language :: Python :: 2.7',
        # We're still lacking support for 3
        #'Programming Language :: Python :: 3',

        'License :: OSI Approved :: GNU General Public License (GPL)',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',

        'Operating System :: POSIX :: Linux',

        'Environment :: X11 Applications :: GTK',

        'Topic :: Desktop Environment',

        'Natural Language :: English',

        'Topic :: Communications :: Email',
        'Topic :: Multimedia :: Video :: Capture',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ]
    )
