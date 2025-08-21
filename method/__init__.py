# coding = 'utf-8'

import os
import sys
from platform import system as _system

__version__ = ['Beta 0.8.15']
major = 3
minor = 13

if sys.version_info < (major, minor):
    raise ImportError(f'Your Python interpreter version is less than {major}.{minor}, please change the interpreter.')

if _system() != 'Windows' and os.name != 'nt':
    raise TypeError('Do not supported system')

__DBG__ = True        # Choose true or false

if __DBG__:
    from .core import *
    from .killer import *
else:
    try:
        from .core import *
        from .killer import *
    except ImportError:
        self_dir = os.path.dirname(os.path.abspath(__file__))
        raise ImportError(f'Missing necessary modules, please run: "{sys.executable}" "{self_dir}\\p_install.py"')
