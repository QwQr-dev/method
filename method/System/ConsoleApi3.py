# coding = 'utf - 8'

from method.System.public_dll import *
from method.System.winusutypes import *


def GetConsoleWindow() -> int:
    GetConsoleWindow = kernel32.GetConsoleWindow
    return GetConsoleWindow()

