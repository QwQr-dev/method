# coding = 'utf-8'

''' 
使用 Python 来调用 Windows API 的一个模块 

项目开源网址：https://github.com/QwQr-dev/method
'''

import os
import sys

__version__ = 'Beta 0.8.61'
_major = 3
_minor = 13

if os.name != 'nt':
    raise TypeError('Do not supported system')

if sys.version_info < (_major, _minor):
    raise ImportError(f'Your Python interpreter version is less than {_major}.{_minor}, please change the interpreter.')

from method.usumd import *
from method.System import *
