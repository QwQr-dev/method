# coding = 'utf-8'
# wchar_s.h

from method.System.winusutypes import *
from method.System.public_dll import msvcrt


def memcpy_s(dest, destSize, src, count):
    memcpy_s = msvcrt.memcpy_s
    memcpy_s.argtypes = [c_void_p, c_size_t, c_void_p, c_size_t]
    memcpy_s.restype = errno_t
    res = memcpy_s(dest, destSize, src, count)
    return res

def wmemcpy_s(dest, destSize, src, count):
    wmemcpy_s = msvcrt.wmemcpy_s
    wmemcpy_s.argtypes = [c_wchar_p, c_size_t, c_wchar_p, c_size_t]
    wmemcpy_s.restype = errno_t
    res = wmemcpy_s(dest, destSize, src, count)
    return res

def memmove_s(dest, numberOfElements, src, count):
    memmove_s = msvcrt.memmove_s
    memmove_s.argtypes = [c_void_p, c_size_t, c_void_p, c_size_t]
    memmove_s.restype = errno_t
    res = memmove_s(dest, numberOfElements, src, count)
    return res

def wmemmove_s(dest, numberOfElements, src, count):
    wmemmove_s = msvcrt.wmemmove_s
    wmemmove_s.argtypes = [c_wchar_p, c_size_t, c_wchar_p, c_size_t]
    wmemmove_s.restype = errno_t
    res = wmemmove_s(dest, numberOfElements, src, count)
    return res
