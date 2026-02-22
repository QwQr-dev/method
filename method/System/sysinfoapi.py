# coding = 'utf - 8'
# sysinfoapi.h

from typing import Any
from method.System.winnt import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck

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


def GetSystemTime():
    GetSystemTime = kernel32.GetSystemTime
    GetSystemTime.restype = VOID
    res = GetSystemTime()
    return res


def GetSystemTimeAsFileTime():
    GetSystemTimeAsFileTime = kernel32.GetSystemTimeAsFileTime
    GetSystemTimeAsFileTime.restype = VOID
    res = GetSystemTimeAsFileTime()
    return res


def GetLocalTime():
    GetLocalTime = kernel32.GetLocalTime
    GetLocalTime.restype = VOID
    res = GetLocalTime()
    return res


def GetNativeSystemInfo():
    GetNativeSystemInfo = kernel32.GetNativeSystemInfo
    GetNativeSystemInfo.restype = VOID
    res = GetNativeSystemInfo()
    return res


def GetTickCount64():
    GetTickCount64 = kernel32.GetTickCount64
    GetTickCount64.restype = ULONGLONG
    res = GetTickCount64()
    return res


class _MEMORYSTATUSEX(Structure):
    _fields_ = [
        ('dwLength', DWORD),
        ('dwMemoryLoad', DWORD),
        ('ullTotalPhys', DWORDLONG),
        ('ullAvailPhys', DWORDLONG),
        ('ullTotalPageFile', DWORDLONG),
        ('ullAvailPageFile', DWORDLONG),
        ('ullTotalVirtual', DWORDLONG),
        ('ullAvailVirtual', DWORDLONG),
        ('ullAvailExtendedVirtual', DWORDLONG)
    ]

MEMORYSTATUSEX = _MEMORYSTATUSEX
LPMEMORYSTATUSEX = POINTER(MEMORYSTATUSEX)


def GetSystemInfo():
    GetSystemInfo = kernel32.GetSystemInfo
    GetSystemInfo.restype = VOID
    res = GetSystemInfo()
    return res


def GlobalMemoryStatusEx(errcheck: bool = True):
    GlobalMemoryStatusEx = kernel32.GlobalMemoryStatusEx
    GlobalMemoryStatusEx.restype = WINBOOL
    res = GlobalMemoryStatusEx()
    return win32_to_errcheck(res, errcheck)


def GetTickCount() -> int:
    GetTickCount = kernel32.GetTickCount
    GetTickCount.restype = DWORD
    return GetTickCount()


def GetSystemTimePreciseAsFileTime():
    GetSystemTimePreciseAsFileTime = kernel32.GetSystemTimePreciseAsFileTime
    GetSystemTimePreciseAsFileTime.restype = VOID
    res = GetSystemTimePreciseAsFileTime()
    return res


def GetVersionEx(lpVersionInformation, unicode: bool = True, errcheck: bool = True):
    GetVersionEx = kernel32.GetVersionExW if unicode else kernel32.GetVersionExA
    GetVersionEx.argtypes = [(LPOSVERSIONINFOW if unicode else LPOSVERSIONINFOA)]
    GetVersionEx.restype = WINBOOL
    res = GetVersionEx(lpVersionInformation)
    return win32_to_errcheck(res, errcheck)


def GetVersion() -> int:
    GetVersion = kernel32.GetVersion
    GetVersion.restype = DWORD
    return GetVersion()


ComputerNameNetBIOS = 0
ComputerNameDnsHostname = 1
ComputerNameDnsDomain = 2
ComputerNameDnsFullyQualified = 3
ComputerNamePhysicalNetBIOS = 4
ComputerNamePhysicalDnsHostname = 5
ComputerNamePhysicalDnsDomain = 6
ComputerNamePhysicalDnsFullyQualified = 7
ComputerNameMax = 8

class _COMPUTER_NAME_FORMAT(enum.Enum):
    ComputerNameNetBIOS = 0
    ComputerNameDnsHostname = 1
    ComputerNameDnsDomain = 2
    ComputerNameDnsFullyQualified = 3
    ComputerNamePhysicalNetBIOS = 4
    ComputerNamePhysicalDnsHostname = 5
    ComputerNamePhysicalDnsDomain = 6
    ComputerNamePhysicalDnsFullyQualified = 7
    ComputerNameMax = 8

COMPUTER_NAME_FORMAT = _COMPUTER_NAME_FORMAT


def SetLocalTime(errcheck: bool = True):
    SetLocalTime = kernel32.SetLocalTime
    SetLocalTime.restype = WINBOOL
    res = SetLocalTime()
    return win32_to_errcheck(res, errcheck)


def GetSystemTimeAdjustment(lpTimeAdjustment, lpTimeIncrement, lpTimeAdjustmentDisabled, errcheck: bool = True):
    GetSystemTimeAdjustment = kernel32.GetSystemTimeAdjustment
    GetSystemTimeAdjustment.argtypes = [PDWORD, PDWORD, PBOOL]
    GetSystemTimeAdjustment.restype = WINBOOL
    res = GetSystemTimeAdjustment(lpTimeAdjustment, lpTimeIncrement, lpTimeAdjustmentDisabled)
    return win32_to_errcheck(res, errcheck)


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


def GetSystemWindowsDirectory(lpBuffer, uSize, unicode: bool = True):
    GetSystemWindowsDirectory = kernel32.GetSystemWindowsDirectoryW if unicode else kernel32.GetSystemWindowsDirectoryA
    GetSystemWindowsDirectory.argtypes = [(LPWSTR if unicode else LPSTR), UINT]
    GetSystemWindowsDirectory.restype = UINT
    res = GetSystemWindowsDirectory(lpBuffer, uSize)
    return res


def GetComputerNameEx(NameType, lpBuffer, nSize, unicode: bool = True, errcheck: bool = True):
    GetComputerNameEx = kernel32.GetComputerNameExW if unicode else kernel32.GetComputerNameExA
    GetComputerNameEx.argtypes = [UINT, (LPWSTR if unicode else LPSTR), LPDWORD]
    GetComputerNameEx.restype = WINBOOL
    res = GetComputerNameEx(NameType, lpBuffer, nSize)
    return win32_to_errcheck(res, errcheck)


def SetComputerNameEx(NameType, lpBuffer, unicode: bool = True, errcheck: bool = True):
    SetComputerNameEx = kernel32.SetComputerNameExW if unicode else kernel32.SetComputerNameExA
    SetComputerNameEx.argtypes = [UINT, (LPCWSTR if unicode else LPCSTR)]
    SetComputerNameEx.restype = WINBOOL
    res = SetComputerNameEx(NameType, lpBuffer)
    return win32_to_errcheck(res, errcheck)


def SetSystemTime(errcheck: bool = True):
    SetSystemTime = kernel32.SetSystemTime
    SetSystemTime.restype = WINBOOL
    res = SetSystemTime()
    return win32_to_errcheck(res, errcheck)


def VerSetConditionMask(ConditionMask, TypeMask, Condition):
    VerSetConditionMask = ntdll.VerSetConditionMask
    VerSetConditionMask.argtypes = [ULONGLONG, ULONG, UCHAR]
    VerSetConditionMask.restype = ULONGLONG
    res = VerSetConditionMask(ConditionMask, TypeMask, Condition)
    return res


def GetOsSafeBootMode(errcheck: bool = True):
    GetOsSafeBootMode = kernel32.GetOsSafeBootMode
    GetOsSafeBootMode.restype = WINBOOL
    res = GetOsSafeBootMode()
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


def GetLogicalProcessorInformation(Buffer, ReturnedLength, errcheck: bool = True):
    GetLogicalProcessorInformation = kernel32.GetLogicalProcessorInformation
    GetLogicalProcessorInformation.argtypes = [PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD]
    GetLogicalProcessorInformation.restype = WINBOOL
    res = GetLogicalProcessorInformation(Buffer, ReturnedLength)
    return win32_to_errcheck(res, errcheck)


def EnumSystemFirmwareTables(FirmwareTableProviderSignature: int, pFirmwareTableEnumBuffer, BufferSize: int) -> int:
    EnumSystemFirmwareTables = kernel32.EnumSystemFirmwareTables
    EnumSystemFirmwareTables.argtypes = [DWORD, PVOID, DWORD]
    EnumSystemFirmwareTables.restype = UINT
    res = EnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableEnumBuffer, BufferSize)
    return res


RSMB = b'RSMB'
ACPI = b'ACPI'
FIRM = b'FIRM'
PCAF = b'PCAF'

class _SMBIOS_HEADER(Structure):
    _fields_ = [('Type', BYTE),
                ('Length', BYTE),
                ('Handle', WORD)
    ]

SMBIOS_HEADER = _SMBIOS_HEADER


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


def GetProductInfo(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType, errcheck: bool = True):
    GetProductInfo = kernel32.GetProductInfo
    GetProductInfo.argtypes = [DWORD, DWORD, DWORD, DWORD, PDWORD]
    GetProductInfo.restype = WINBOOL
    res = GetProductInfo(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType)
    return win32_to_errcheck(res, errcheck)


def GetLogicalProcessorInformationEx(RelationshipType, Buffer, ReturnedLength, errcheck: bool = True):
    GetLogicalProcessorInformationEx = kernel32.GetLogicalProcessorInformationEx
    GetLogicalProcessorInformationEx.argtypes = [UINT, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, PDWORD]
    GetLogicalProcessorInformationEx.restype = WINBOOL
    res = GetLogicalProcessorInformationEx(RelationshipType, Buffer, ReturnedLength)
    return win32_to_errcheck(res, errcheck)

