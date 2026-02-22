# coding = 'utf-8'

from typing import Any
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck

# tlhelp32.h

MAX_MODULE_NAME32 = 255


def CreateToolhelp32Snapshot(dwFlags: int, th32ProcessID: int, errcheck: bool = True) -> int:
    CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
    CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
    CreateToolhelp32Snapshot.restype = HANDLE
    res = CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    return win32_to_errcheck(res, errcheck)


INVALID_HANDLE_VALUE = HANDLE(LONG_PTR(-1).value).value

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS =  0x00000002
TH32CS_SNAPTHREAD =   0x00000004
TH32CS_SNAPMODULE =   0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPALL =      (TH32CS_SNAPHEAPLIST | 
                       TH32CS_SNAPPROCESS | 
                       TH32CS_SNAPTHREAD | 
                       TH32CS_SNAPMODULE
)

TH32CS_INHERIT =      0x80000000

class tagHEAPLIST32(Structure):
    _fields_ = [('dwSize', SIZE_T),
                ('th32ProcessID', DWORD),
                ('th32HeapID', ULONG_PTR),
                ('dwFlags', DWORD)
    ]

HEAPLIST32 = tagHEAPLIST32
PHEAPLIST32 = POINTER(HEAPLIST32)
LPHEAPLIST32 = PHEAPLIST32

HF32_DEFAULT = 1
HF32_SHARED = 2


def Heap32ListFirst(hSnapshot: int, lphl: Any, errcheck: bool = True):
    Heap32ListFirst = kernel32.Heap32ListFirst
    Heap32ListFirst.argtypes = [HANDLE, LPHEAPLIST32]
    Heap32ListFirst.restype = WINBOOL
    res = Heap32ListFirst(hSnapshot, lphl)
    return win32_to_errcheck(res, errcheck)


def Heap32ListNext(hSnapshot: int, lphl: Any, errcheck: bool = True):
    Heap32ListNext = kernel32.Heap32ListNext
    Heap32ListNext.argtypes = [HANDLE, LPHEAPLIST32]
    Heap32ListNext.restype = WINBOOL
    res = Heap32ListNext(hSnapshot, lphl)
    return win32_to_errcheck(res, errcheck)


class tagHEAPENTRY32(Structure):
    _fields_ = [('dwSize', SIZE_T),
                ('hHandle', HANDLE),
                ('dwAddress', ULONG_PTR),
                ('dwBlockSize', SIZE_T),
                ('dwFlags', DWORD),
                ('dwLockCount', DWORD),
                ('dwResvd', DWORD),
                ('th32ProcessID', DWORD),
                ('th32HeapID', ULONG_PTR),
    ]

HEAPENTRY32 = tagHEAPENTRY32
PHEAPENTRY32 = POINTER(HEAPENTRY32)
LPHEAPENTRY32 = PHEAPENTRY32

LF32_FIXED = 0x00000001
LF32_FREE = 0x00000002
LF32_MOVEABLE = 0x00000004


def Heap32First(lphe: Any, th32ProcessID: int, th32HeapID: int, errcheck: bool = True):
    Heap32First = kernel32.Heap32First
    Heap32First.argtypes = [LPHEAPENTRY32, DWORD, ULONG_PTR]
    Heap32First.restype = WINBOOL
    res = Heap32First(lphe, th32ProcessID, th32HeapID)
    return win32_to_errcheck(res, errcheck)


def Heap32Next(lphe: Any, errcheck: bool = True):
    Heap32Next = kernel32.Heap32Next
    Heap32Next.argtypes = [LPHEAPENTRY32]
    Heap32Next.restype = WINBOOL
    res = Heap32Next(lphe)
    return win32_to_errcheck(res, errcheck)


def Toolhelp32ReadProcessMemory(
    th32ProcessID: int, 
    lpBaseAddress: Any, 
    lpBuffer: int, 
    cbRead: int, 
    lpNumberOfBytesRead: Any,
    errcheck: bool = True
):
    
    Toolhelp32ReadProcessMemory = kernel32.Toolhelp32ReadProcessMemory
    Toolhelp32ReadProcessMemory.argtypes = [
        DWORD,
        LPCVOID,
        LPVOID,
        SIZE_T,
        PSIZE_T
    ]

    Toolhelp32ReadProcessMemory.restype = WINBOOL
    res = Toolhelp32ReadProcessMemory(
        th32ProcessID, 
        lpBaseAddress, 
        lpBuffer, 
        cbRead, 
        lpNumberOfBytesRead
    )

    return win32_to_errcheck(res, errcheck)


class tagPROCESSENTRY32(Structure):
    _fields_ = [('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ProcessID', DWORD),
                ('th32DefaultHeapID', ULONG_PTR),
                ('th32ModuleID', DWORD),
                ('cntThreads', DWORD),
                ('th32ParentProcessID', DWORD),
                ('pcPriClassBase', LONG),
                ('dwFlags', DWORD),
                ('szExeFile', CHAR * MAX_PATH),
    ]

PROCESSENTRY32 = tagPROCESSENTRY32
PPROCESSENTRY32 = POINTER(PROCESSENTRY32)
LPPPROCESSENTRY32 = PPROCESSENTRY32

class tagPROCESSENTRY32W(Structure):
    _fields_ = [('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ProcessID', DWORD),
                ('th32DefaultHeapID', ULONG_PTR),
                ('th32ModuleID', DWORD),
                ('cntThreads', DWORD),
                ('th32ParentProcessID', DWORD),
                ('pcPriClassBase', LONG),
                ('dwFlags', DWORD),
                ('szExeFile', WCHAR * MAX_PATH)
    ]

PROCESSENTRY32W = tagPROCESSENTRY32W
PPROCESSENTRY32W = POINTER(PROCESSENTRY32W)
LPPROCESSENTRY32W = PPROCESSENTRY32W

if UNICODE:
    PROCESSENTRY32 = PROCESSENTRY32W
    PPROCESSENTRY32 = PPROCESSENTRY32W
    LPPROCESSENTRY32 = LPPROCESSENTRY32W


def Process32First(hSnapshot: int, lppe: Any, unicode: bool = True, errcheck: bool = True):
    Process32First = (kernel32.Process32FirstW 
                      if unicode else kernel32.Process32First
    )

    Process32First.argtypes = [
        HANDLE, 
        POINTER(PROCESSENTRY32W if unicode else tagPROCESSENTRY32)
    ]
    
    Process32First.restype = WINBOOL
    res = Process32First(hSnapshot, lppe)
    return win32_to_errcheck(res, errcheck)


def Process32Next(hSnapshot: int, lppe: Any, unicode: bool = True, errcheck: bool = True):
    Process32Next = (kernel32.Process32NextW 
                      if unicode else kernel32.Process32Next
    )

    Process32Next.argtypes = [
        HANDLE, 
        POINTER(PROCESSENTRY32W if unicode else tagPROCESSENTRY32)       
    ]
    
    Process32Next.restype = WINBOOL
    res = Process32Next(hSnapshot, lppe)
    return win32_to_errcheck(res, errcheck)


class tagTHREADENTRY32(Structure):
    _fields_ = [('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ThreadID', DWORD),
                ('th32OwnerProcessID', DWORD),
                ('tpBasePri', LONG),
                ('tpDeltaPri', LONG),
                ('dwFlags', DWORD)
    ]

THREADENTRY32 = tagTHREADENTRY32
PTHREADENTRY32 = POINTER(THREADENTRY32)
LPTHREADENTRY32 = PTHREADENTRY32


def Thread32First(hSnapshot: int, lpte: Any, errcheck: bool = True):
    Thread32First = kernel32.Thread32First
    res = Thread32First(hSnapshot, lpte)
    return win32_to_errcheck(res, errcheck)


def Thread32Next(hSnapshot: int, lpte: Any, errcheck: bool = True):
    Thread32Next = kernel32.Thread32Next
    Thread32Next.argtypes = [
        HANDLE,
        LPTHREADENTRY32
    ]

    Thread32Next.restype = WINBOOL
    res = Thread32Next(hSnapshot, lpte)
    return win32_to_errcheck(res, errcheck)


class tagMODULEENTRY32W(Structure):
    _fields_ = [('dwSize', DWORD),
                ('th32ModuleID', DWORD),
                ('th32ProcessID', DWORD),
                ('GlblcntUsage', DWORD),
                ('ProccntUsage', DWORD),
                ('modBaseAddr', PBYTE),
                ('modBaseSize', DWORD),
                ('hModule', HMODULE),
                ('szModule', WCHAR * (MAX_MODULE_NAME32 + 1)),
                ('szExePath', WCHAR * MAX_PATH)
    ]

MODULEENTRY32W = tagMODULEENTRY32W
PMODULEENTRY32W = POINTER(MODULEENTRY32W)
LPMODULEENTRY32W = PMODULEENTRY32W

class tagMODULEENTRY32(Structure):
    _fields_ = [('dwSize', DWORD),
                ('th32ModuleID', DWORD),
                ('th32ProcessID', DWORD),
                ('GlblcntUsage', DWORD),
                ('ProccntUsage', DWORD),
                ('modBaseAddr', PBYTE),
                ('modBaseSize', DWORD),
                ('hModule', HMODULE),
                ('szModule', CHAR * (MAX_MODULE_NAME32 + 1)),
                ('szExePath', CHAR * MAX_PATH)
    ]

MODULEENTRY32 = tagMODULEENTRY32
PMODULEENTRY32 = POINTER(MODULEENTRY32)
LPMODULEENTRY32 = PMODULEENTRY32

if UNICODE:
    MODULEENTRY32 = MODULEENTRY32W
    PMODULEENTRY32 = PMODULEENTRY32W
    LPMODULEENTRY32 = LPMODULEENTRY32W


def Module32First(hSnapshot: int, lpme: Any, unicode: bool = True, errcheck: bool = True):
    Module32First = kernel32.Module32FirstW if unicode else kernel32.Module32First
    Module32First.argtypes = [
        HANDLE,
        POINTER(MODULEENTRY32W if unicode else tagMODULEENTRY32)
    ]

    Module32First.restype = WINBOOL
    res = Module32First(hSnapshot, lpme)
    return win32_to_errcheck(res, errcheck)


def Module32Next(hSnapshot: int, lpme: Any, unicode: bool = True, errcheck: bool = True):
    Module32Next = kernel32.Module32NextW if unicode else kernel32.Module32Next
    Module32Next.argtypes = [
        HANDLE,
        POINTER(MODULEENTRY32W if unicode else tagMODULEENTRY32)      
    ]

    Module32Next.restype = WINBOOL
    res = Module32Next(hSnapshot, lpme)
    return win32_to_errcheck(res, errcheck)

