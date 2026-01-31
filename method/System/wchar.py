# coding = 'utf-8'
# wchar.h

from method.System.winusutypes import *
from method.System.public_dll import msvcrt

def wmemchr(buffer, c, count):
    wmemchr = msvcrt.wmemchr
    wmemchr.argtypes = [c_wchar_t_p, c_wchar_t, c_size_t]
    wmemchr.restype = c_wchar_t_p
    res = wmemchr(buffer, c, count)
    return res

def wmemcmp(buffer1, buffer2, count):
    wmemcmp = msvcrt.wmemcmp
    wmemcmp.argtypes = [c_wchar_t_p, c_wchar_t_p, c_size_t]
    wmemcmp.restype = c_int
    res = wmemcmp(buffer1, buffer2, count)
    return res


def wmemcpy(dest, src, count):
    wmemcpy = msvcrt.wmemcpy
    wmemcpy.argtypes = [c_wchar_p, c_wchar_p, c_size_t]
    wmemcpy.restype = c_wchar_p
    res = wmemcpy(dest, src, count)
    return res

def wmemmove(dest, src, count):
    wmemmove = msvcrt.wmemmove
    wmemmove.argtypes = [c_wchar_p, c_wchar_p, c_size_t]
    wmemmove.restype = c_wchar_p
    res = wmemmove(dest, src, count)
    return res

def wmemset(dest, c, count):
    wmemset = msvcrt.wmemset
    wmemset.argtypes = [c_wchar_t_p, c_wchar_t, c_size_t]
    wmemset.restype = c_wchar_t_p
    res = wmemset(dest, c, count)
    return res

def wcsstr(_Str: str, _SubStr: str):
    wcsstr = msvcrt.wcsstr
    wcsstr.argtypes = [c_wchar_t_p, c_wchar_t_p]
    wcsstr.restype = c_wchar_t_p
    res = wcsstr(_Str, _SubStr)
    return res

def memchr(buffer, c, count):
    memchr = msvcrt.memchr
    memchr.argtypes = [c_void_p, c_int, c_size_t]
    memchr.restype = c_void_p
    res = memchr(buffer, c, count)
    return res

def memcpy(dest, src, count):
    memcpy = msvcrt.memcpy
    memcpy.argtypes = [c_void, c_void, c_size_t]
    memcpy.restype = c_void
    res = memcpy(dest, src, count)
    return res

def memmove(dest, src, count):
    memmove = msvcrt.memmove
    memmove.argtypes = [c_void, c_void, c_size_t]
    memmove.restype = c_void
    res = memmove(dest, src, count)
    return res

def memset(dest, c, count):
    memset = msvcrt.memset
    memset.argtypes = [c_void, c_int, c_size_t]
    memset.restype = c_void
    res = memset(dest, c, count)
    return res

def memcmp(buffer1, buffer2, count):
    memcmp = msvcrt.memcmp
    memcmp.argtypes = [c_void, c_void, c_size_t]
    memcmp.restype = c_int
    res = memcmp(buffer1, buffer2, count)
    return res


def _wtoi(string: str) -> int:
    _wtoi = msvcrt._wtoi
    _wtoi.argtypes = [c_wchar_p]
    _wtoi.restype = c_int
    res = _wtoi(string)
    return res
