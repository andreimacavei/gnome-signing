# -*- coding: utf-8 -*-

import os, sys
import locale
import gettext

import logging
log = logging.getLogger()

#  The translation files will be under
#  @LOCALE_DIR@/@LANGUAGE@/LC_MESSAGES/@APP_NAME@.mo
APP_NAME = "gnome-keysign"

# APP_DIR = os.path.join (sys.prefix, 'share')
# LOCALE_DIR = os.path.join(APP_DIR, 'i18n') # .mo files will then be located in APP_Dir/i18n/LANGUAGECODE/LC_MESSAGES/
LOCALE_DIR = 'build/locale'
# Now we need to choose the language. We will provide a list, and gettext
# will use the first translation available in the list
DEFAULT_LANGUAGES = os.environ.get('LANG', '').split(':')
DEFAULT_LANGUAGES += ['en_US']

lc, encoding = locale.getdefaultlocale()
if lc:
    languages = [lc]

# Concat all languages (env + default locale),
#  and here we have the languages and location of the translations
languages += DEFAULT_LANGUAGES
mo_location = LOCALE_DIR

kwargs = {}
if sys.version_info[0] < 3:
    # This matches the default behavior under Python 3, although
    # that keyword argument is not present in the Python 3 API.
    kwargs['unicode'] = True

gettext.install(APP_NAME, **kwargs)

gettext.find(APP_NAME, mo_location)

gettext.textdomain(APP_NAME)

gettext.bind_textdomain_codeset(APP_NAME, "UTF-8")

log.info("The path to .mo files is %s", mo_location)
language = gettext.translation(APP_NAME, mo_location, languages=languages, fallback=True)