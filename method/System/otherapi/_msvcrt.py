# coding = 'utf-8'

from method.System.winusutypes import *
from method.System.public_dll import msvcrt
from method.System.errcheck import errno_to_errcheck


def malloc(Size, errcheck: bool = True) -> (int | None):
    malloc = msvcrt.malloc
    malloc.argtypes = [c_size_t]
    malloc.restype = c_void_p
    res = malloc(Size)
    return errno_to_errcheck(res, errcheck)
