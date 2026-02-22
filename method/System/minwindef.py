# coding = 'utf-8'

from method.System.winusutypes import *

PSZ = PCHAR

def MAKEWORD(a,b):
    return WORD((BYTE((DWORD_PTR(a).value) & 0xff).value) | 
                (WORD(BYTE((DWORD_PTR(b).value) & 0xff).value).value) << 8
                ).value

def MAKELONG(a, b):
    return LONG((WORD((DWORD_PTR(a).value) & 0xffff).value) | 
                (DWORD(WORD((DWORD_PTR(b).value) & 0xffff)).value) << 16
                ).value

def LOWORD(l: int) -> int:
    return WORD((DWORD_PTR(l).value) & 0xffff).value

def HIWORD(l: int) -> int:
    return WORD((DWORD_PTR(l).value >> 16) & 0xffff).value

def LOBYTE(w: int) -> int:
    return BYTE(DWORD_PTR(w).value & 0xff).value

def HIBYTE(w: int) -> int:
    return BYTE((DWORD_PTR(w).value >> 8) & 0xff).value

SPHANDLE = PHANDLE 
LPHANDLE = PHANDLE 
HGLOBAL = HANDLE 
GLOBALHANDLE = HANDLE 
LOCALHANDLE = HANDLE 

class _FILETIME(Structure):
    _fields_ = [
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', DWORD)
    ]

FILETIME = _FILETIME
PFILETIME = POINTER(FILETIME)
LPFILETIME = PFILETIME
