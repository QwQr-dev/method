# coding = 'utf-8'

from method.System.winusutypes import *
from method.System.public_dll import Psapi
from method.System.errcheck import win32_to_errcheck

def GetModuleBaseName(
    hProcess, 
    hModule, 
    lpBaseName, 
    nSize, 
    unicode: bool = True, 
    errcheck: bool = True
):
    
    GetModuleBaseName = Psapi.GetModuleBaseNameW if unicode else Psapi.GetModuleBaseNameA
    GetModuleBaseName.argtypes = [HANDLE, HMODULE, (LPWSTR if unicode else LPSTR), DWORD]
    GetModuleBaseName.restype = DWORD
    res = GetModuleBaseName(hProcess, hModule, lpBaseName, nSize)
    return win32_to_errcheck(res, errcheck)