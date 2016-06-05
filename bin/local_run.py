#!/usr/bin/env python
# coding: utf-8
import sys
import os.path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')))

from scp import run_app

if __name__ == "__main__":
    run_app()
