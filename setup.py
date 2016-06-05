# -*- coding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import scp as module

setup(name='SfkConnetionPoint',
      version=module.__version__,
      description='sfk connection point for NPTV Cloud',
      author=module.__author__,
      author_email='d.mikhalchenko@undev.ru',
      packages=[
          'scp',
          'scp.protobufs'
      ],
      scripts=['bin/sfk-connection-point']
      )
