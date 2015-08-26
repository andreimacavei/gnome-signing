#!/usr/bin/env python

from keysign import __version__ as version

from setuptools import setup, find_packages
import setuptools.command.build_py

from keysign.misc.i18n import build_translations

class BuildPyCommand(setuptools.command.build_py.build_py):
    def run(self):
        setuptools.command.build_py.build_py.run(self)


if __name__ == '__main__':
    maintainers = 'Andrei Macavei'
    maintainers_emails = ('andrei.macavei89@gmail.com')

    data_files = build_translations() + [
            ('share/applications', ['data/gnome-keysign.desktop']),
            # Hm, hicolor/scalable doesn't seem to work so well
            #('share/icons/hicolor/scalable', ['data/gnome-keysign.svg']),
            ('share/icons', ['data/gnome-keysign.svg']),
        ]

    setup(
        name = 'gnome-keysign',
        version = version,
        description = 'OpenPGP key signing helper',
        author = maintainers+', Tobias Mueller',
        author_email = maintainers_emails+', tobiasmue@gnome.org',
        # maintainer=maintainers,
        # maintainer_email=maintainers_emails,
        packages = [
            'keysign',
            'keysign.compat',
            'keysign.network',
            'keysign.gpg',
            'keysign.misc'],
        #package_dir={'keysign': 'keysign'},
        #package_data={'keysign': ['data/']},
        data_files=data_files,
        include_package_data = True,
        #scripts = ['gnome-keysign.py'],
        install_requires=[
            # Note that the dependency on <= 2.2 is only
            # to not confuse Ubuntu 14.04's pip as that
            # seems incompatible with a newer requests library.
            # https://bugs.launchpad.net/ubuntu/+source/python-pip/+bug/1306991
            'requests<=2.2',
            'qrcode',
            'pygpgme' # this requires libgpgme which is not in cheeseshop
            # avahi # no entry in the cheeseshop
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
            'build_py': BuildPyCommand,
        },
        classifiers = [
            'Development Status :: 4 - Beta',

            'Environment :: X11 Applications :: GTK',

            'Intended Audience :: Developers',
            'Intended Audience :: System Administrators',
            'Intended Audience :: End Users/Desktop',
            'Intended Audience :: Information Technology',
            'Intended Audience :: Legal Industry',
            'Intended Audience :: Telecommunications Industry',

            'License :: OSI Approved :: GNU General Public License (GPL)',
            'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',

            'Natural Language :: English',

            'Programming Language :: Python',
            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 2.7',
            # We're still lacking support for 3
            #'Programming Language :: Python :: 3',

            'Operating System :: POSIX :: Linux',

            'Topic :: Desktop Environment',
            'Topic :: Communications :: Email',
            'Topic :: Multimedia :: Video :: Capture',
            'Topic :: Security :: Cryptography',
            'Topic :: Software Development :: Libraries :: Python Modules',
            ]
        )
