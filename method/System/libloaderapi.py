# coding = 'utf-8'
# libloaderapi.h

from typing import Any
from method.System.sdkddkver import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck

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


def FindResource(hModule, lpName, lpType, unicode: bool = True, errcheck: bool = True):
    FindResource = kernel32.FindResourceW if unicode else kernel32.FindResourceA
    res = FindResource(hModule, lpName, lpType)
    return win32_to_errcheck(res, errcheck)    


def EnumResourceNames(hModule, lpType, lpEnumFunc, lParam, unicode: bool = True, errcheck: bool = True):
    EnumResourceNames = (kernel32.EnumResourceNamesW 
                         if unicode else kernel32.EnumResourceNamesA
    )

    res = EnumResourceNames(hModule, lpType, lpEnumFunc, lParam)
    return win32_to_errcheck(res, errcheck)    


def FreeResource(hResData, errcheck: bool = True):
    FreeResource = kernel32.FreeResource
    res = FreeResource(hResData)
    return win32_to_errcheck(res, errcheck)    


def LoadResource(hModule, hResInfo, errcheck: bool = True):
    LoadResource = kernel32.LoadResource
    res = LoadResource(hModule, hResInfo)
    return win32_to_errcheck(res, errcheck)  


def LockResource(hResData, errcheck: bool = True):
    LockResource = kernel32.LockResource
    LockResource.restype = LPVOID
    res = LockResource(hResData)
    return win32_to_errcheck(res, errcheck)  


def AddDllDirectory(NewDirectory, errcheck: bool = True):
    AddDllDirectory = kernel32.AddDllDirectory
    res = AddDllDirectory(NewDirectory)
    return win32_to_errcheck(res, errcheck)  


def RemoveDllDirectory(Cookie, errcheck: bool = True):
    RemoveDllDirectory = kernel32.RemoveDllDirectory
    res = RemoveDllDirectory(Cookie)
    return win32_to_errcheck(res, errcheck)    


def SetDefaultDllDirectories(DirectoryFlags, errcheck: bool = True):
    SetDefaultDllDirectories = kernel32.SetDefaultDllDirectories
    res = SetDefaultDllDirectories(DirectoryFlags)
    return win32_to_errcheck(res, errcheck)    


def EnumResourceLanguages(
    hModule, 
    lpType, 
    lpName, 
    lpEnumFunc, 
    lParam, 
    unicode: bool = True,
    errcheck: bool = True
):

    EnumResourceLanguages = (kernel32.EnumResourceLanguagesW 
                             if unicode else kernel32.EnumResourceLanguagesA
    )

    res = EnumResourceLanguages(
        hModule, 
        lpType, 
        lpName, 
        lpEnumFunc, 
        lParam
    )

    return win32_to_errcheck(res, errcheck)    


def EnumResourceLanguagesEx(
    hModule, 
    lpType, 
    lpName, 
    lpEnumFunc, 
    lParam, 
    dwFlags, 
    LangId, 
    unicode: bool = True,
    errcheck: bool  = True
):
    
    EnumResourceLanguagesEx = (kernel32.EnumResourceLanguagesExW 
                               if unicode else kernel32.EnumResourceLanguagesExA
    )

    res = EnumResourceLanguagesEx(
        hModule, 
        lpType, 
        lpName, 
        lpEnumFunc, 
        lParam, 
        dwFlags, 
        LangId
    )

    return win32_to_errcheck(res, errcheck)    


def EnumResourceNamesEx(
    hModule, 
    lpType, 
    lpEnumFunc, 
    lParam, 
    dwFlags, 
    LangId, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    EnumResourceNamesEx = (kernel32.EnumResourceNamesExW 
                           if unicode else kernel32.EnumResourceNamesExA
    )

    res = EnumResourceNamesEx(
        hModule, 
        lpType, 
        lpEnumFunc, 
        lParam, 
        dwFlags, 
        LangId
    )

    return win32_to_errcheck(res, errcheck)    


def EnumResourceTypesEx(
    hModule, 
    lpEnumFunc, 
    lParam, 
    dwFlags, 
    LangId, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    EnumResourceTypesEx = (kernel32.EnumResourceTypesExW 
                           if unicode else kernel32.EnumResourceTypesExA
    )

    res = EnumResourceTypesEx(
        hModule, 
        lpEnumFunc, 
        lParam, 
        dwFlags, 
        LangId
    )

    return win32_to_errcheck(res, errcheck)    


def QueryOptionalDelayLoadedAPI(CallerModule, lpDllName, lpProcName, Reserved, errcheck: bool = True):
    QueryOptionalDelayLoadedAPI = kernel32.QueryOptionalDelayLoadedAPI
    res = QueryOptionalDelayLoadedAPI(CallerModule, lpDllName, lpProcName, Reserved)
    return win32_to_errcheck(res, errcheck)    


def LoadLibrary(lpLibFileName: str, unicode: bool = True, errcheck: bool = True) -> int:
    LoadLibrary = (kernel32.LoadLibraryW 
                   if unicode else kernel32.LoadLibraryA
    )

    LoadLibrary.argtypes = [LPCWSTR if unicode else LPCSTR]
    LoadLibrary.restype = HMODULE
    res = LoadLibrary(lpLibFileName)
    return win32_to_errcheck(res, errcheck)  


def FreeLibraryAndExitThread(hLibModule, dwExitCode, errcheck: bool = True) -> None:
    FreeLibraryAndExitThread = kernel32.FreeLibraryAndExitThread
    FreeLibraryAndExitThread(hLibModule, dwExitCode)


def DisableThreadLibraryCalls(hLibModule, errcheck: bool = True):
    DisableThreadLibraryCalls = kernel32.DisableThreadLibraryCalls
    res = DisableThreadLibraryCalls(hLibModule)
    return win32_to_errcheck(res, errcheck)  


def FreeLibrary(hLibModule, errcheck: bool = True):
    FreeLibrary = kernel32.FreeLibrary
    res = FreeLibrary(hLibModule)
    return win32_to_errcheck(res, errcheck)  


def GetProcAddress(hModule: int, lpProcName: str | int, encoding: str = 'ansi', errcheck: bool = True) -> int:
    GetProcAddress = kernel32.GetProcAddress

    if isinstance(lpProcName, str):
        lpProcName = lpProcName.encode(encoding)

    GetProcAddress.argtypes = [HMODULE, LPCSTR]
    GetProcAddress.restype = FARPROC
    res = GetProcAddress(hModule, lpProcName)
    return win32_to_errcheck(res, errcheck)  


def GetModuleFileName(hModule, lpFilename, nSize, unicode: bool = True, errcheck: bool = True):
    GetModuleFileName = (kernel32.GetModuleFileNameW 
                         if unicode else kernel32.GetModuleFileNameA
    )
    
    res = GetModuleFileName(hModule, lpFilename, nSize)
    return win32_to_errcheck(res, errcheck)


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


def FindStringOrdinal(
    dwFindStringOrdinalFlags, 
    lpStringSource, 
    cchSource, 
    lpStringValue, 
    cchValue, 
    bIgnoreCase,
    errcheck: bool = True
):
    
    FindStringOrdinal = kernel32.FindStringOrdinal
    res = FindStringOrdinal(dwFindStringOrdinalFlags, 
                            lpStringSource, 
                            cchSource, 
                            lpStringValue, 
                            cchValue, 
                            bIgnoreCase
    )

    return win32_to_errcheck(res, errcheck)


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


def FindResourceEx(hModule, lpType, lpName, wLanguage, unicode: bool = True, errcheck: bool = True):
    FindResourceEx = kernel32.FindResourceExW if unicode else kernel32.FindResourceExA
    res = FindResourceEx(hModule, lpType, lpName, wLanguage)
    return win32_to_errcheck(res, errcheck)  


def GetModuleHandle(lpModuleName: str, unicode: bool = True, errcheck: bool = True) -> int:
    GetModuleHandle = (kernel32.GetModuleHandleW 
                       if unicode else kernel32.GetModuleHandleA
    )

    GetModuleHandle.argtypes = [LPCWSTR if unicode else LPCSTR]
    GetModuleHandle.restype = HMODULE
    res = GetModuleHandle(lpModuleName)

    return win32_to_errcheck(res, errcheck)  


def GetModuleHandleEx(
    dwFlags: int, 
    lpModuleName: str, 
    phModule: Any, 
    unicode: bool = True,
    errcheck: bool = True
) -> int:
    
    GetModuleHandleEx = (kernel32.GetModuleHandleExW 
                         if unicode else kernel32.GetModuleHandleExA
    )

    GetModuleHandleEx.argtypes = [DWORD, 
                                  (LPCWSTR if unicode else LPCSTR), 
                                  HMODULE
    ]

    GetModuleHandleEx.restype = BOOL
    res = GetModuleHandleEx(dwFlags, lpModuleName, phModule)
    return win32_to_errcheck(res, errcheck)    


def LoadLibraryEx(
        lpLibFileName: str, 
        hFile: int, 
        dwFlags: int, 
        unicode: bool = True,
        errcheck: bool = True
) -> int:
    
    LoadLibraryEx = (kernel32.LoadLibraryExW 
                     if unicode else kernel32.LoadLibraryExA
    )

    LoadLibraryEx.argtypes = [(LPCWSTR if unicode else LPCSTR), HANDLE, DWORD]
    LoadLibraryEx.restype = HMODULE
    res = LoadLibraryEx(lpLibFileName, hFile, dwFlags)
    return win32_to_errcheck(res, errcheck)  


def SizeofResource(hModule, hResInfo, errcheck: bool = True):
    SizeofResource = kernel32.SizeofResource
    res = SizeofResource(hModule, hResInfo)
    return win32_to_errcheck(res, errcheck)  


PGET_MODULE_HANDLE_EXA = WINAPI(WINBOOL, DWORD, LPCSTR, HMODULE)
PGET_MODULE_HANDLE_EXW = WINAPI(WINBOOL, DWORD, LPCWSTR, HMODULE)
PGET_MODULE_HANDLE_EX = PGET_MODULE_HANDLE_EXW if UNICODE else PGET_MODULE_HANDLE_EXA


def LoadString(hInstance, uID, lpBuffer, cchBufferMax, unicode: bool = True):
    LoadString = user32.LoadStringW if unicode else user32.LoadStringA
    res = LoadString(hInstance, uID, lpBuffer, cchBufferMax)
    return res


def LoadPackagedLibrary(lpwLibFileName, Reserved, errcheck: bool = True):
    LoadPackagedLibrary = kernel32.LoadPackagedLibrary
    res = LoadPackagedLibrary(lpwLibFileName, Reserved)
    return win32_to_errcheck(res, errcheck)  
