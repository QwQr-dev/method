# coding = 'utf-8'

''' 
使用 Python 来调用 Windows API 的一个模块 

项目开源网址：https://github.com/QwQr-dev/method
'''

import os
import sys

__version__ = 'Beta 0.8.59'
major = 3
minor = 13

if os.name != 'nt':
    raise TypeError('Do not supported system')

if sys.version_info < (major, minor):
    raise ImportError(f'Your Python interpreter version is less than {major}.{minor}, please change the interpreter.')

from .usumd import *
from .killer import *
from .System import *
