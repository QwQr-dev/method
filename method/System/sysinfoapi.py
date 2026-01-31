# coding = 'utf - 8'

from typing import Any
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck

# sysinfoapi.h

class _SYSTEM_INFO(Structure):
    class DUMMYUNIONNAME(Union):
        class DUMMYSTRUCTNAME(Structure):
            _fields_ = [
                ('wProcessorArchitecture', WORD),
                ('wReserved', WORD)
            ]
        
        _anonymous_ = ['DUMMYSTRUCTNAME']
        _fields_ = [
            ('dwOemId', DWORD),
            ('DUMMYSTRUCTNAME', DUMMYSTRUCTNAME)
        ]
    
    _anonymous_ = ['DUMMYUNIONNAME']
    _fields_ = [
        ('dwPageSize', DWORD),
        ('lpMinimumApplicationAddress', LPVOID),
        ('lpMaximumApplicationAddress', LPVOID),
        ('dwActiveProcessorMask', DWORD_PTR),
        ('dwNumberOfProcessors', DWORD),
        ('dwProcessorType', DWORD),
        ('dwAllocationGranularity', DWORD),
        ('wProcessorLevel', WORD),
        ('wProcessorRevision', WORD),
        ('DUMMYUNIONNAME', DUMMYUNIONNAME)
    ]

SYSTEM_INFO = _SYSTEM_INFO
LPSYSTEM_INFO = POINTER(SYSTEM_INFO)


def GetWindowsDirectory(
    lpBuffer: Any, 
    uSize: int, 
    unicode: bool = True,
    errcheck: bool = True
) -> int:
    
    GetWindowsDirectory = (kernel32.GetWindowsDirectoryW 
                           if unicode else kernel32.GetWindowsDirectoryA
    )
    
    GetWindowsDirectory.argtypes = [
        (LPWSTR if unicode else LPSTR),
        UINT
    ]

    GetWindowsDirectory.restype = UINT
    res = GetWindowsDirectory(lpBuffer, uSize)
    return win32_to_errcheck(res, errcheck)


def GetSystemDirectory(
    lpBuffer: Any, 
    uSize: int, 
    unicode: bool = True,
    errcheck: bool = True
) -> int:

    GetSystemDirectory = (kernel32.GetSystemDirectoryW 
                          if unicode else kernel32.GetSystemDirectoryA
    )

    GetSystemDirectory.argtypes = [
        (LPWSTR if unicode else LPSTR),
        UINT
    ]

    GetSystemDirectory.restype = UINT
    res = GetSystemDirectory(lpBuffer, uSize)
    return win32_to_errcheck(res, errcheck)



def GetSystemWow64Directory(
    lpBuffer: Any, 
    uSize: int, 
    unicode: bool = True,
    errcheck: bool = True
) -> int:
    
    GetSystemWow64Directory = (kernel32.GetSystemWow64DirectoryW 
                               if unicode else kernel32.GetSystemWow64DirectoryA
    )
    
    GetSystemWow64Directory.argtypes = [
        (LPWSTR if unicode else LPSTR),
        UINT
    ]

    GetSystemWow64Directory.restype = UINT
    res = GetSystemWow64Directory(lpBuffer, uSize)
    return win32_to_errcheck(res, errcheck)


def GetVersion() -> int:
    GetVersion = kernel32.GetVersion
    GetVersion.restype = DWORD
    return GetVersion()


RSMB = b'RSMB'
ACPI = b'ACPI'
FIRM = b'FIRM'
PCAF = b'PCAF'


def GetSystemFirmwareTable(
    FirmwareTableProviderSignature: int | str | bytes, 
    FirmwareTableID: int, 
    BufferSize: int,
    pFirmwareTableBuffer: int,
    errcheck: bool = True
) -> int:
    
    if not isinstance(FirmwareTableProviderSignature, int):
        if isinstance(FirmwareTableProviderSignature, str):
            FirmwareTableProviderSignature = FirmwareTableProviderSignature.encode()
        FirmwareTableProviderSignature = int.from_bytes(FirmwareTableProviderSignature)
    
    GetSystemFirmwareTable = kernel32.GetSystemFirmwareTable
    GetSystemFirmwareTable.argtypes = [
        DWORD,
        DWORD,
        PVOID,
        DWORD
    ]

    GetSystemFirmwareTable.restype = UINT
    res = GetSystemFirmwareTable(
        FirmwareTableProviderSignature,
        FirmwareTableID, 
        pFirmwareTableBuffer,
        BufferSize
    )
    
    return win32_to_errcheck(res, errcheck)


class _SMBIOS_HEADER(Structure):
    _fields_ = [('Type', BYTE),
                ('Length', BYTE),
                ('Handle', WORD)
    ]

SMBIOS_HEADER = _SMBIOS_HEADER
