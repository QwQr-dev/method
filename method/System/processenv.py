# coding = 'utf-8'
# processenv.h

from method.System.public_dll import *
from method.System.winusutypes import *


def GetCommandLine(unicode: bool = True) -> (str | bytes):
    GetCommandLine = kernel32.GetCommandLineW if unicode else kernel32.GetCommandLineA
    GetCommandLine.restype = LPWSTR if unicode else LPSTR
    res = GetCommandLine()
    return res
