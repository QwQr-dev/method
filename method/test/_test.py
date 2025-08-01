# coding = 'utf-8'

import os
import re
from win32com import client


def ispath(path: str, path_exists_check: bool = False, lenpathcheck: bool = True):
    '''Path syntax check.（路径语法检查）'''

    if not path:
        raise TypeError('The path cannot be empty or None')
        
    if len(path) > 259 and lenpathcheck:
        raise TypeError('The path length cannot exceed 260 characters')
    
    path = os.path.normpath(path)
    drive, tem_path = os.path.splitdrive(path)
    if drive:
        if not re.fullmatch(r"[A-Za-z]:", drive):
            raise TypeError('Invalid file path')
   
        if tem_path == '' or list(tem_path)[0] != '\\':
            raise TypeError('Invalid file path')
    else:
        raise TypeError('Invalid file path')

    RESERVED_NAMES = ['CON', 'PRN', 'AUX', 'NUL','COM1', 'COM2', 'COM3', 
                      'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 
                      'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 
                      'LPT7', 'LPT8', 'LPT9']
    INVALID_CHARS = ['<', '>', ':', '"', '|', '?', '*', '/', '\\']
    tem_path = path.split('\\')
    del tem_path[0]
    p = ', '
    num = 0
    for part in tem_path:
        if any(c in INVALID_CHARS for c in part):
            raise TypeError(f'The following keywords must not be contained in the file path: "{p.join(INVALID_CHARS)}"')

        name_Windows = part.split('.')[0].upper()
        if name_Windows in RESERVED_NAMES:
            raise TypeError(f'The following keywords must not be contained in the file path: "{p.join(RESERVED_NAMES)}"')

        try:
            if part[-1] in [' ', '.']:
                raise TypeError('The end of the file name must not contain spaces or "."')
        except IndexError:
            pass

        if part.strip() == '' and num < len(path):
            raise TypeError('The path cannot be empty')

        if len(part) > 255 and lenpathcheck:
            raise FileExistsError('File names or folder names must not exceed 256 characters')
        num += 1

    if not os.path.exists(path) and path_exists_check:
        raise FileExistsError('The file path does not exist')


def ispath_return_bool(path, path_exists_check, lenpathcheck):
    try:
        ispath(path=path, 
               path_exists_check=path_exists_check, 
               lenpathcheck=lenpathcheck)
        return True
    except Exception:
        return False

