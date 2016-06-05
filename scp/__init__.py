# coding: utf-8

from eventlet import monkey_patch
monkey_patch()

from optparse import OptionParser
from scp.logger import LOGGER


import dosca
import sys

__version__ = '0.3.6'

__author__ = 'Dima Mikhalchenko'


def run_app():
    p = OptionParser()
    p.add_option('--config', default='')
    p.add_option('--noauth', default=False, action='store_true')

    options, _ = p.parse_args()
    if not options.config:
        print >> sys.stderr, "Provide path to config!"
        sys.exit(1)

    if not options.noauth:
        LOGGER.info("Userbase authorization of sfks is needed by default. \
            If you want to start SCP for some debugging purposes, \
            provide --noauth command line key.")
    else:
        LOGGER.info("Userbase authorization switched off")


    config = dosca.parse_file(options.config)

    LOGGER.info('Sfk Connection Point ver. %s' % __version__)
    
    import main
    main.NEED_AUTH = not options.noauth
    main.run(config)
