# coding = 'utf-8'
# libloaderapi.h

from typing import Any
from ctypes import Structure, WinError, POINTER

try:
    from sdkddkver import *
    from public_dll import *
    from win_cbasictypes import *
    from error import GetLastError
except ImportError:
    from .sdkddkver import *
    from .public_dll import *
    from .win_cbasictypes import *
    from .error import GetLastError

MAX_PATH = 260
FARPROC = INT_PTR

#####################################################################
class tagENUMUILANG(Structure):
    _fields_ = [('NumOfEnumUILang', ULONG),
                ('SizeOfEnumUIBuffer', ULONG),
                ('pEnumUIBuffer', POINTER(LANGID))
    ]

ENUMUILANG = tagENUMUILANG
PENUMUILANG = POINTER(ENUMUILANG)

ENUMRESLANGPROCA = CALLBACK(WINBOOL, HMODULE, LPCSTR, LPCSTR, WORD, LONG_PTR)
ENUMRESLANGPROCW = CALLBACK(WINBOOL, HMODULE, LPCWSTR, LPCWSTR, WORD, LONG_PTR)
ENUMRESNAMEPROCA = CALLBACK(WINBOOL, HMODULE, LPCSTR, LPSTR, LONG_PTR)
ENUMRESNAMEPROCW = CALLBACK(WINBOOL, HMODULE, LPCWSTR, LPWSTR, LONG_PTR)
ENUMRESTYPEPROCA = CALLBACK(WINBOOL, HMODULE, LPSTR, LONG_PTR)
ENUMRESTYPEPROCW = CALLBACK(WINBOOL, HMODULE, LPWSTR, LONG_PTR)

ENUMRESLANGPROC = ENUMRESLANGPROCW if UNICODE else ENUMRESLANGPROCA
ENUMRESNAMEPROC = ENUMRESNAMEPROCW if UNICODE else ENUMRESNAMEPROCA
ENUMRESTYPEPROC = ENUMRESTYPEPROCW if UNICODE else ENUMRESTYPEPROCA

DLL_DIRECTORY_COOKIE = PVOID
PDLL_DIRECTORY_COOKIE = POINTER(PVOID)

FIND_RESOURCE_DIRECTORY_TYPES = 0x0100
FIND_RESOURCE_DIRECTORY_NAMES = 0x0200
FIND_RESOURCE_DIRECTORY_LANGUAGES = 0x0400

RESOURCE_ENUM_LN = 0x0001
RESOURCE_ENUM_MUI = 0x0002
RESOURCE_ENUM_MUI_SYSTEM = 0x0004
RESOURCE_ENUM_VALIDATE = 0x0008
RESOURCE_ENUM_MODULE_EXACT = 0x0010

SUPPORT_LANG_NUMBER = 32

GET_MODULE_HANDLE_EX_FLAG_PIN = 0x1
GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x2
GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x4


def FindResource(hModule, lpName, lpType, unicode: bool = True):
    FindResource = Kernel32.FindResourceW if unicode else Kernel32.FindResourceA
    res = FindResource(hModule, lpName, lpType)
    if not res:
        raise WinError(GetLastError())
    

def EnumResourceNames(hModule, lpType, lpEnumFunc, lParam, unicode: bool = True):
    EnumResourceNames = (Kernel32.EnumResourceNamesW 
                         if unicode else Kernel32.EnumResourceNamesA
    )

    res = EnumResourceNames(hModule, lpType, lpEnumFunc, lParam)
    if not res:
        raise WinError(GetLastError())
    

def FreeResource(hResData):
    FreeResource = Kernel32.FreeResource
    res = FreeResource(hResData)
    if not res:
        raise WinError(GetLastError())
    

def LoadResource(hModule, hResInfo):
    LoadResource = Kernel32.LoadResource
    res = LoadResource(hModule, hResInfo)
    if not res:
        raise WinError(GetLastError())
    return res


def LockResource(hResData):
    LockResource = Kernel32.LockResource
    LockResource.restype = LPVOID
    res = LockResource(hResData)
    if not res:
        raise WinError(GetLastError())
    return res


def AddDllDirectory(NewDirectory):
    AddDllDirectory = Kernel32.AddDllDirectory
    res = AddDllDirectory(NewDirectory)
    if not res:
        raise WinError(GetLastError())
    return res


def RemoveDllDirectory(Cookie):
    RemoveDllDirectory = Kernel32.RemoveDllDirectory
    res = RemoveDllDirectory(Cookie)
    if not res:
        raise WinError(GetLastError())
    

def SetDefaultDllDirectories(DirectoryFlags):
    SetDefaultDllDirectories = Kernel32.SetDefaultDllDirectories
    res = SetDefaultDllDirectories(DirectoryFlags)
    if not res:
        raise WinError(GetLastError())
    

def EnumResourceLanguages(hModule, 
                          lpType, 
                          lpName, 
                          lpEnumFunc, 
                          lParam, 
                          unicode: bool = True):
    
    EnumResourceLanguages = (Kernel32.EnumResourceLanguagesW 
                             if unicode else Kernel32.EnumResourceLanguagesA
    )

    res = EnumResourceLanguages(hModule, 
                                lpType, 
                                lpName, 
                                lpEnumFunc, 
                                lParam
    )

    if not res:
        raise WinError(GetLastError())
    

def EnumResourceLanguagesEx(hModule, 
                            lpType, 
                            lpName, 
                            lpEnumFunc, 
                            lParam, 
                            dwFlags, 
                            LangId, 
                            unicode: bool = True):
    
    EnumResourceLanguagesEx = (Kernel32.EnumResourceLanguagesExW 
                               if unicode else Kernel32.EnumResourceLanguagesExA
    )

    res = EnumResourceLanguagesEx(hModule, 
                                  lpType, 
                                  lpName, 
                                  lpEnumFunc, 
                                  lParam, 
                                  dwFlags, 
                                  LangId
    )

    if not res:
        raise WinError(GetLastError())
    

def EnumResourceNamesEx(hModule, 
                        lpType, 
                        lpEnumFunc, 
                        lParam, 
                        dwFlags, 
                        LangId, 
                        unicode: bool = True):
    
    EnumResourceNamesEx = (Kernel32.EnumResourceNamesExW 
                           if unicode else Kernel32.EnumResourceNamesExA
    )

    res = EnumResourceNamesEx(hModule, 
                              lpType, 
                              lpEnumFunc, 
                              lParam, 
                              dwFlags, 
                              LangId
    )

    if not res:
        raise WinError(GetLastError())
    

def EnumResourceTypesEx(hModule, 
                        lpEnumFunc, 
                        lParam, 
                        dwFlags, 
                        LangId, 
                        unicode: bool = True):
    
    EnumResourceTypesEx = (Kernel32.EnumResourceTypesExW 
                           if unicode else Kernel32.EnumResourceTypesExA
    )

    res = EnumResourceTypesEx(hModule, 
                              lpEnumFunc, 
                              lParam, 
                              dwFlags, 
                              LangId
    )

    if not res:
        raise WinError(GetLastError())
    

def QueryOptionalDelayLoadedAPI(CallerModule, lpDllName, lpProcName, Reserved):
    QueryOptionalDelayLoadedAPI = Kernel32.QueryOptionalDelayLoadedAPI
    res = QueryOptionalDelayLoadedAPI(CallerModule, lpDllName, lpProcName, Reserved)
    if not res:
        raise WinError(GetLastError())
    

def LoadLibrary(lpLibFileName: str, unicode: bool = True) -> int:
    LoadLibrary = (Kernel32.LoadLibraryW 
                   if unicode else Kernel32.LoadLibraryA
    )

    LoadLibrary.argtypes = [LPCWSTR if unicode else LPCSTR]
    LoadLibrary.restype = HMODULE
    res = LoadLibrary(lpLibFileName)
    
    if not res:
        raise WinError(GetLastError())
    return res


def FreeLibraryAndExitThread(hLibModule, dwExitCode) -> None:
    FreeLibraryAndExitThread = Kernel32.FreeLibraryAndExitThread
    FreeLibraryAndExitThread(hLibModule, dwExitCode)


def DisableThreadLibraryCalls(hLibModule):
    DisableThreadLibraryCalls = Kernel32.DisableThreadLibraryCalls
    res = DisableThreadLibraryCalls(hLibModule)
    if not res:
        raise WinError(GetLastError())
    return res


def FreeLibrary(hLibModule):
    FreeLibrary = Kernel32.FreeLibrary
    res = FreeLibrary(hLibModule)
    if not res:
        raise WinError(GetLastError())
    return res


def GetProcAddress(hModule: int, lpProcName: str | int, encoding: str = 'ansi') -> int:
    GetProcAddress = Kernel32.GetProcAddress

    if isinstance(lpProcName, str):
        lpProcName = lpProcName.encode(encoding)

    GetProcAddress.argtypes = [HMODULE, LPCSTR]
    GetProcAddress.restype = FARPROC
    res = GetProcAddress(hModule, lpProcName)
    if not res:
        raise WinError(GetLastError())
    return res


def GetModuleFileName(hModule, lpFilename, nSize, unicode: bool = True):
    GetModuleFileName = (Kernel32.GetModuleFileNameW 
                         if unicode else Kernel32.GetModuleFileNameA
    )
    
    res = GetModuleFileName(hModule, lpFilename, nSize)
    if not res:
        raise WinError(GetLastError())


CURRENT_IMPORT_REDIRECTION_VERSION = 1

class _REDIRECTION_FUNCTION_DESCRIPTOR(Structure):
    _fields_ = [('DllName', PCSTR),
                ('FunctionName', PCSTR),
                ('RedirectionTarget', PVOID)
    ]

REDIRECTION_FUNCTION_DESCRIPTOR = _REDIRECTION_FUNCTION_DESCRIPTOR
PREDIRECTION_FUNCTION_DESCRIPTOR = POINTER(REDIRECTION_FUNCTION_DESCRIPTOR)

PCREDIRECTION_FUNCTION_DESCRIPTOR = PREDIRECTION_FUNCTION_DESCRIPTOR

class _REDIRECTION_DESCRIPTOR(Structure):
    _fields_ = [('Version', ULONG),
                ('FunctionCount', ULONG),
                ('Redirections', PCREDIRECTION_FUNCTION_DESCRIPTOR)
    ]

REDIRECTION_DESCRIPTOR = _REDIRECTION_DESCRIPTOR
PREDIRECTION_DESCRIPTOR = POINTER(REDIRECTION_DESCRIPTOR)

PCREDIRECTION_DESCRIPTOR = PREDIRECTION_DESCRIPTOR

def FindStringOrdinal(dwFindStringOrdinalFlags, 
                      lpStringSource, 
                      cchSource, 
                      lpStringValue, 
                      cchValue, 
                      bIgnoreCase):
    
    FindStringOrdinal = Kernel32.FindStringOrdinal
    res = FindStringOrdinal(dwFindStringOrdinalFlags, 
                            lpStringSource, 
                            cchSource, 
                            lpStringValue, 
                            cchValue, 
                            bIgnoreCase
    )

    if res == -1:
        raise WinError(GetLastError())
    return res


DONT_RESOLVE_DLL_REFERENCES = 0x1
LOAD_LIBRARY_AS_DATAFILE = 0x2
LOAD_WITH_ALTERED_SEARCH_PATH = 0x8
LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x10
LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20
LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x40
LOAD_LIBRARY_REQUIRE_SIGNED_TARGET = 0x80
LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x100
LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x200
LOAD_LIBRARY_SEARCH_USER_DIRS = 0x400
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800
LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x1000

if NTDDI_VERSION >= NTDDI_WIN10_RS1:
    LOAD_LIBRARY_SAFE_CURRENT_DIRS = 0x00002000
    LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER = 0x00004000
else:
    LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER = LOAD_LIBRARY_SEARCH_SYSTEM32

if NTDDI_VERSION >= NTDDI_WIN10_RS2:
    LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY = 0x00008000


def FindResourceEx(hModule, lpType, lpName, wLanguage, unicode: bool = True):
    FindResourceEx = Kernel32.FindResourceExW if unicode else Kernel32.FindResourceExA
    res = FindResourceEx(hModule, lpType, lpName, wLanguage)
    if not res:
        raise WinError(GetLastError())
    return res


def GetModuleHandle(lpModuleName: str, unicode: bool = True) -> int:
    GetModuleHandle = (Kernel32.GetModuleHandleW 
                       if unicode else Kernel32.GetModuleHandleA
    )

    GetModuleHandle.argtypes = [LPCWSTR if unicode else LPCSTR]
    GetModuleHandle.restype = HMODULE
    res = GetModuleHandle(lpModuleName)

    if not res:
        raise WinError(GetLastError())
    return res


def GetModuleHandleEx(dwFlags: int, 
                      lpModuleName: str, 
                      phModule: Any, 
                      unicode: bool = True) -> int:
    
    GetModuleHandleEx = (Kernel32.GetModuleHandleExW 
                         if unicode else Kernel32.GetModuleHandleExA
    )

    GetModuleHandleEx.argtypes = [DWORD, 
                                  (LPCWSTR if unicode else LPCSTR), 
                                  HMODULE
    ]

    GetModuleHandleEx.restype = BOOL
    res = GetModuleHandleEx(dwFlags, lpModuleName, phModule)
    if not res:
        raise WinError(GetLastError())
    

def LoadLibraryEx(lpLibFileName: str, 
                  hFile: int, 
                  dwFlags: int, 
                  unicode: bool = True) -> int:
    
    LoadLibraryEx = (Kernel32.LoadLibraryExW 
                     if unicode else Kernel32.LoadLibraryExA
    )

    LoadLibraryEx.argtypes = [(LPCWSTR if unicode else LPCSTR), HANDLE, DWORD]
    LoadLibraryEx.restype = HMODULE
    res = LoadLibraryEx(lpLibFileName, hFile, dwFlags)
    if not res:
        raise WinError(GetLastError())
    return res


def SizeofResource(hModule, hResInfo):
    SizeofResource = Kernel32.SizeofResource
    res = SizeofResource(hModule, hResInfo)
    if not res:
        raise WinError(GetLastError())
    return res


PGET_MODULE_HANDLE_EXA = WINAPI(WINBOOL, DWORD, LPCSTR, HMODULE)
PGET_MODULE_HANDLE_EXW = WINAPI(WINBOOL, DWORD, LPCWSTR, HMODULE)
PGET_MODULE_HANDLE_EX = PGET_MODULE_HANDLE_EXW if UNICODE else PGET_MODULE_HANDLE_EXA


def LoadString(hInstance, uID, lpBuffer, cchBufferMax, unicode: bool = True):
    LoadString = User32.LoadStringW if unicode else User32.LoadStringA
    res = LoadString(hInstance, uID, lpBuffer, cchBufferMax)
    return res


def LoadPackagedLibrary(lpwLibFileName, Reserved):
    LoadPackagedLibrary = Kernel32.LoadPackagedLibrary
    res = LoadPackagedLibrary(lpwLibFileName, Reserved)
    if not res:
        raise WinError(GetLastError())
    return res
