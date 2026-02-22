# coding = 'utf-8'
# libloaderapi.h

from typing import Any
from method.System.sdkddkver import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck
from method.System.win32typing import WinFunctionType

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


def FindResource(hModule: int, lpName: str | bytes, lpType, unicode: bool = True, errcheck: bool = True):
    FindResource = kernel32.FindResourceW if unicode else kernel32.FindResourceA
    FindResource.argtypes = [
        HMODULE,
        (LPCWSTR if unicode else LPCSTR)
    ]

    FindResource.restype = HRSRC
    res = FindResource(hModule, lpName, lpType)
    return win32_to_errcheck(res, errcheck)    


def EnumResourceNames(
    hModule: int, 
    lpType: str | bytes, 
    lpEnumFunc: WinFunctionType, 
    lParam: int, 
    unicode: bool = True, 
    errcheck: bool = True
):
    
    EnumResourceNames = (kernel32.EnumResourceNamesW 
                         if unicode else kernel32.EnumResourceNamesA
    )

    EnumResourceNames.argtypes = [
        HMODULE,
        (LPCWSTR if unicode else LPCSTR),
        (ENUMRESLANGPROCW if unicode else ENUMRESLANGPROCA),
        LONG_PTR
    ]

    EnumResourceNames.restype = WINBOOL
    res = EnumResourceNames(hModule, lpType, lpEnumFunc, lParam)
    return win32_to_errcheck(res, errcheck)    


def FreeResource(hResData: Any, errcheck: bool = True):
    FreeResource = kernel32.FreeResource
    FreeResource.argtypes = [HGLOBAL]
    FreeResource.restype = WINBOOL
    res = FreeResource(hResData)
    return win32_to_errcheck(res, errcheck)    


def LoadResource(hModule: int, hResInfo: Any, errcheck: bool = True):
    LoadResource = kernel32.LoadResource
    LoadResource.argtypes = [
        HMODULE,
        HRSRC
    ]

    LoadResource.restype = HGLOBAL
    res = LoadResource(hModule, hResInfo)
    return win32_to_errcheck(res, errcheck)  


def LockResource(hResData: int, errcheck: bool = True):
    LockResource = kernel32.LockResource
    LockResource.argtypes = [HGLOBAL]
    LockResource.restype = LPVOID
    res = LockResource(hResData)
    return win32_to_errcheck(res, errcheck)  


def AddDllDirectory(NewDirectory: str, errcheck: bool = True):
    AddDllDirectory = kernel32.AddDllDirectory
    AddDllDirectory.argtypes = [PCWSTR]
    AddDllDirectory.restype = DLL_DIRECTORY_COOKIE
    res = AddDllDirectory(NewDirectory)
    return win32_to_errcheck(res, errcheck)  


def RemoveDllDirectory(Cookie: Any, errcheck: bool = True):
    RemoveDllDirectory = kernel32.RemoveDllDirectory
    RemoveDllDirectory.argtypes = [DLL_DIRECTORY_COOKIE]
    RemoveDllDirectory.restype = WINBOOL
    res = RemoveDllDirectory(Cookie)
    return win32_to_errcheck(res, errcheck)    


def SetDefaultDllDirectories(DirectoryFlags: int, errcheck: bool = True):
    SetDefaultDllDirectories = kernel32.SetDefaultDllDirectories
    SetDefaultDllDirectories.argtypes = [DWORD]
    SetDefaultDllDirectories.restype = WINBOOL
    res = SetDefaultDllDirectories(DirectoryFlags)
    return win32_to_errcheck(res, errcheck)    


def EnumResourceLanguages(
    hModule: int, 
    lpType: str | bytes, 
    lpName: str | bytes, 
    lpEnumFunc: WinFunctionType, 
    lParam: int, 
    unicode: bool = True,
    errcheck: bool = True
):

    EnumResourceLanguages = (kernel32.EnumResourceLanguagesW 
                             if unicode else kernel32.EnumResourceLanguagesA
    )

    EnumResourceLanguages.argtypes = [
        HMODULE,
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        (ENUMRESLANGPROCW if unicode else ENUMRESLANGPROCA),
        LONG_PTR
    ]

    EnumResourceLanguages.restype = WINBOOL
    res = EnumResourceLanguages(
        hModule, 
        lpType, 
        lpName, 
        lpEnumFunc, 
        lParam
    )

    return win32_to_errcheck(res, errcheck)    


def EnumResourceLanguagesEx(
    hModule: int, 
    lpType: str | bytes, 
    lpName: str | bytes, 
    lpEnumFunc: WinFunctionType, 
    lParam: int, 
    dwFlags: int, 
    LangId: int, 
    unicode: bool = True,
    errcheck: bool  = True
):
    
    EnumResourceLanguagesEx = (kernel32.EnumResourceLanguagesExW 
                               if unicode else kernel32.EnumResourceLanguagesExA
    )

    EnumResourceLanguagesEx.argtypes = [
        HMODULE,
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        (ENUMRESLANGPROCW if unicode else ENUMRESLANGPROCA),
        LONG_PTR,
        DWORD,
        LANGID
    ]

    EnumResourceLanguagesEx.restype = WINBOOL
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
    hModule: int, 
    lpType: str | bytes, 
    lpEnumFunc: WinFunctionType, 
    lParam: int, 
    dwFlags: int, 
    LangId: int, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    EnumResourceNamesEx = (kernel32.EnumResourceNamesExW 
                           if unicode else kernel32.EnumResourceNamesExA
    )

    EnumResourceNamesEx.argtypes = [
        HMODULE,
        (LPCWSTR if unicode else LPCSTR),
        (ENUMRESLANGPROCW if unicode else ENUMRESLANGPROCA),
        LONG_PTR,
        DWORD,
        LANGID
    ]

    EnumResourceNamesEx.restype = WINBOOL
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
    hModule: int, 
    lpEnumFunc: WinFunctionType, 
    lParam: int, 
    dwFlags: int, 
    LangId: int, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    EnumResourceTypesEx = (kernel32.EnumResourceTypesExW 
                           if unicode else kernel32.EnumResourceTypesExA
    )

    EnumResourceTypesEx.argtypes = [
        HMODULE,
        (ENUMRESLANGPROCW if unicode else ENUMRESLANGPROCA),
        LONG_PTR,
        DWORD,
        LANGID
    ]

    EnumResourceTypesEx.restype = WINBOOL
    res = EnumResourceTypesEx(
        hModule, 
        lpEnumFunc, 
        lParam, 
        dwFlags, 
        LangId
    )

    return win32_to_errcheck(res, errcheck)    


def QueryOptionalDelayLoadedAPI(
    CallerModule: int, 
    lpDllName: bytes, 
    lpProcName: bytes, 
    Reserved: bytes, 
    errcheck: bool = True
):

    QueryOptionalDelayLoadedAPI = kernel32.QueryOptionalDelayLoadedAPI
    QueryOptionalDelayLoadedAPI.argtypes = [HMODULE, LPCSTR, LPCSTR, DWORD]
    QueryOptionalDelayLoadedAPI.restype = WINBOOL
    res = QueryOptionalDelayLoadedAPI(CallerModule, lpDllName, lpProcName, Reserved)
    return win32_to_errcheck(res, errcheck)    


def LoadLibrary(lpLibFileName: str | bytes, unicode: bool = True, errcheck: bool = True) -> int:
    LoadLibrary = (kernel32.LoadLibraryW 
                   if unicode else kernel32.LoadLibraryA
    )

    LoadLibrary.argtypes = [LPCWSTR if unicode else LPCSTR]
    LoadLibrary.restype = HMODULE
    res = LoadLibrary(lpLibFileName)
    return win32_to_errcheck(res, errcheck)  


def FreeLibraryAndExitThread(hLibModule: int, dwExitCode: int) -> None:
    FreeLibraryAndExitThread = kernel32.FreeLibraryAndExitThread
    FreeLibraryAndExitThread.argtypes = [HMODULE, DWORD]
    FreeLibraryAndExitThread.restype = VOID
    FreeLibraryAndExitThread(hLibModule, dwExitCode)


def DisableThreadLibraryCalls(hLibModule: int, errcheck: bool = True):
    DisableThreadLibraryCalls = kernel32.DisableThreadLibraryCalls
    DisableThreadLibraryCalls.argtypes = [HMODULE]
    DisableThreadLibraryCalls.restype = WINBOOL
    res = DisableThreadLibraryCalls(hLibModule)
    return win32_to_errcheck(res, errcheck)  


def FreeLibrary(hLibModule: int, errcheck: bool = True):
    FreeLibrary = kernel32.FreeLibrary
    FreeLibrary.argtypes = [HMODULE]
    FreeLibrary.restype = WINBOOL
    res = FreeLibrary(hLibModule)
    return win32_to_errcheck(res, errcheck)  


def GetProcAddress(
    hModule: int, 
    lpProcName: str | bytes | int, 
    errcheck: bool = True
) -> int:
    
    GetProcAddress = kernel32.GetProcAddress
    if isinstance(lpProcName, str):
        lpProcName = lpProcName.encode('ansi')

    GetProcAddress.argtypes = [HMODULE, LPCSTR]
    GetProcAddress.restype = FARPROC
    res = GetProcAddress(hModule, lpProcName)
    return win32_to_errcheck(res, errcheck)  


def GetModuleFileName(
    hModule: int, 
    lpFilename: str | bytes, 
    nSize: int, 
    unicode: bool = True, 
    errcheck: bool = True
):
    
    GetModuleFileName = (kernel32.GetModuleFileNameW 
                         if unicode else kernel32.GetModuleFileNameA
    )
    
    GetModuleFileName.argtypes = [
        HMODULE,
        (LPWSTR if unicode else LPSTR),
        DWORD
    ]

    GetModuleFileName.restype = DWORD
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
    dwFindStringOrdinalFlags: int, 
    lpStringSource: str, 
    cchSource: int, 
    lpStringValue: str, 
    cchValue: int, 
    bIgnoreCase: int,
    errcheck: bool = True
):
    
    FindStringOrdinal = kernel32.FindStringOrdinal
    FindStringOrdinal.argtypes = [
        DWORD,
        LPCWSTR,
        INT,
        LPCWSTR,
        INT,
        WINBOOL
    ]
    
    FindStringOrdinal.restype = INT
    res = FindStringOrdinal(
        dwFindStringOrdinalFlags, 
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


def FindResourceEx(
    hModule: int, 
    lpType: str | bytes, 
    lpName: str | bytes, 
    wLanguage: int, 
    unicode: bool = True, 
    errcheck: bool = True
):
    
    FindResourceEx = kernel32.FindResourceExW if unicode else kernel32.FindResourceExA
    FindResourceEx.argtypes = [
        HMODULE,
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        WORD
    ]

    FindResourceEx.restype = HRSRC
    res = FindResourceEx(hModule, lpType, lpName, wLanguage)
    return win32_to_errcheck(res, errcheck)  


def GetModuleHandle(lpModuleName: str | bytes, unicode: bool = True, errcheck: bool = True) -> int:
    GetModuleHandle = (kernel32.GetModuleHandleW 
                       if unicode else kernel32.GetModuleHandleA
    )

    GetModuleHandle.argtypes = [LPCWSTR if unicode else LPCSTR]
    GetModuleHandle.restype = HMODULE
    res = GetModuleHandle(lpModuleName)
    return win32_to_errcheck(res, errcheck)  


def GetModuleHandleEx(
    dwFlags: int, 
    lpModuleName: str | bytes, 
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
        lpLibFileName: str | bytes, 
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


def SizeofResource(hModule: int, hResInfo: int, errcheck: bool = True):
    SizeofResource = kernel32.SizeofResource
    SizeofResource.argtypes = [HMODULE, HRSRC]
    SizeofResource.restype = DWORD
    res = SizeofResource(hModule, hResInfo)
    return win32_to_errcheck(res, errcheck)  


PGET_MODULE_HANDLE_EXA = WINAPI(WINBOOL, DWORD, LPCSTR, HMODULE)
PGET_MODULE_HANDLE_EXW = WINAPI(WINBOOL, DWORD, LPCWSTR, HMODULE)
PGET_MODULE_HANDLE_EX = PGET_MODULE_HANDLE_EXW if UNICODE else PGET_MODULE_HANDLE_EXA


def LoadString(hInstance: int, uID: int, lpBuffer: Any, cchBufferMax: int, unicode: bool = True):
    LoadString = user32.LoadStringW if unicode else user32.LoadStringA
    LoadString.argtypes = [
        HINSTANCE,
        UINT,
        (LPWSTR if unicode else LPSTR),
        INT
    ]

    LoadString.restype = INT
    res = LoadString(hInstance, uID, lpBuffer, cchBufferMax)
    return res


def LoadPackagedLibrary(lpwLibFileName: str, Reserved: int, errcheck: bool = True):
    LoadPackagedLibrary = kernel32.LoadPackagedLibrary
    LoadPackagedLibrary.argtypes = [LPCWSTR, DWORD]
    LoadPackagedLibrary.restype = HMODULE
    res = LoadPackagedLibrary(lpwLibFileName, Reserved)
    return win32_to_errcheck(res, errcheck)  
