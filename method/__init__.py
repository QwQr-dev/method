# coding = 'utf-8'

import os
import sys
from platform import system as _system

__version__ = ['Beta 0.8.0']

if sys.version_info < (3, 13):
    raise ImportError('Your Python interpreter version is less than 3.13, please change the interpreter.')

if _system() != 'Windows':
    raise TypeError('Sorry, no other operating systems other than Windows.')

try:
    from . import test
    from .device_method import *
except ImportError:
    self_dir = os.path.dirname(os.path.abspath(__file__))
    raise ImportError(f'Missing necessary modules, please run: "{sys.executable}" "{self_dir}\\p_install.py"')
