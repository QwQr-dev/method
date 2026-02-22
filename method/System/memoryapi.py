# coding = 'utf-8'
# memoryapi.h

import enum
from typing import Any
from method.System.winnt import *
from method.System.sdkddkver import *
from method.System.minwindef import *
from method.System.minwinbase import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck


##################################################################
# from winnt.h
DELETE  = 0x00010000
READ_CONTROL  = 0x00020000
WRITE_DAC  = 0x00040000
WRITE_OWNER  = 0x00080000
SYNCHRONIZE  = 0x00100000

STANDARD_RIGHTS_REQUIRED  = 0x000F0000
STANDARD_RIGHTS_READ = READ_CONTROL
STANDARD_RIGHTS_WRITE = READ_CONTROL
STANDARD_RIGHTS_EXECUTE = READ_CONTROL
STANDARD_RIGHTS_ALL  = 0x001F0000

SECTION_QUERY = 0x0001
SECTION_MAP_WRITE = 0x0002
SECTION_MAP_READ = 0x0004
SECTION_MAP_EXECUTE = 0x0008
SECTION_EXTEND_SIZE = 0x0010
SECTION_MAP_EXECUTE_EXPLICIT = 0x0020

SECTION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                      SECTION_QUERY | 
                      SECTION_MAP_WRITE | 
                      SECTION_MAP_READ | 
                      SECTION_MAP_EXECUTE | 
                      SECTION_EXTEND_SIZE
)

SESSION_QUERY_ACCESS = 0x1
SESSION_MODIFY_ACCESS = 0x2

SESSION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                      SESSION_QUERY_ACCESS | 
                      SESSION_MODIFY_ACCESS
)

##############################################################
LowMemoryResourceNotification = 0
HighMemoryResourceNotification = 1

class _MEMORY_RESOURCE_NOTIFICATION_TYPE(enum.IntFlag):
    LowMemoryResourceNotification = 0
    HighMemoryResourceNotification = 1

MEMORY_RESOURCE_NOTIFICATION_TYPE = _MEMORY_RESOURCE_NOTIFICATION_TYPE

class _WIN32_MEMORY_RANGE_ENTRY(Structure):
    _fields_ = [('VirtualAddress', PVOID),
                ('NumberOfBytes', SIZE_T)
    ]

WIN32_MEMORY_RANGE_ENTRY = _WIN32_MEMORY_RANGE_ENTRY
PWIN32_MEMORY_RANGE_ENTRY = POINTER(WIN32_MEMORY_RANGE_ENTRY)


def VirtualFree(lpAddress, dwSize, dwFreeType, errcheck: bool = True):
    VirtualFree = kernel32.VirtualFree
    VirtualFree.argtypes = [LPVOID, SIZE_T, DWORD]
    VirtualFree.restype = WINBOOL
    res = VirtualFree(lpAddress, dwSize, dwFreeType)
    return win32_to_errcheck(res, errcheck)


def VirtualAlloc(lpAddress: int, dwSize: int, flAllocationType: int, flProtect: int, errcheck: bool = True) -> int:
    VirtualAlloc = kernel32.VirtualAlloc
    VirtualAlloc.argtypes = [LPVOID, SIZE_T, DWORD, DWORD]
    VirtualAlloc.restype = LPVOID
    res = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
    return win32_to_errcheck(res, errcheck)


def VirtualAllocEx(
    hProcess: int, 
    lpAddress: int, 
    dwSize: int, 
    flAllocationType: int, 
    flProtect: int,
    errcheck: bool = True
) -> int:
    
    VirtualAllocEx = kernel32.VirtualAllocEx
    VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
    VirtualAllocEx.restype = LPVOID
    res = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
    return win32_to_errcheck(res, errcheck)    


FILE_MAP_WRITE = SECTION_MAP_WRITE
FILE_MAP_READ = SECTION_MAP_READ
FILE_MAP_ALL_ACCESS = SECTION_ALL_ACCESS
FILE_MAP_COPY = 0x1
FILE_MAP_RESERVE = 0x80000000
FILE_MAP_TARGETS_INVALID = 0x40000000
FILE_MAP_LARGE_PAGES = 0x20000000



def VirtualQuery(lpAddress, lpBuffer, dwLength, errcheck: bool = True):
    VirtualQuery = kernel32.VirtualQuery
    VirtualQuery.argtypes = [LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T]
    VirtualQuery.restype = SIZE_T
    res = VirtualQuery(lpAddress, lpBuffer, dwLength)
    return win32_to_errcheck(res, errcheck)


def FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush, errcheck: bool = True):
    FlushViewOfFile = kernel32.FlushViewOfFile
    FlushViewOfFile.argtypes = [LPCVOID, SIZE_T]
    FlushViewOfFile.restype = WINBOOL
    res = FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush)
    return win32_to_errcheck(res, errcheck)


def UnmapViewOfFile(lpBaseAddress, errcheck: bool = True):
    UnmapViewOfFile = kernel32.UnmapViewOfFile
    UnmapViewOfFile.argtypes = [LPCVOID]
    UnmapViewOfFile.restype = WINBOOL
    res = UnmapViewOfFile(lpBaseAddress)
    return win32_to_errcheck(res, errcheck)


def UnmapViewOfFile2(Process, BaseAddress, UnmapFlags, errcheck: bool = True):
    UnmapViewOfFile2 = kernel32.UnmapViewOfFile2
    UnmapViewOfFile2.argtypes = [HANDLE, PVOID, ULONG]
    UnmapViewOfFile2.restype = WINBOOL
    res = UnmapViewOfFile2(Process, BaseAddress, UnmapFlags)
    return win32_to_errcheck(res, errcheck)


def CreateFileMappingFromApp(hFile, SecurityAttributes, PageProtection, MaximumSize, Name, errcheck: bool = True):
    CreateFileMappingFromApp = kernel32.CreateFileMappingFromApp
    CreateFileMappingFromApp.argtypes = [HANDLE, PSECURITY_ATTRIBUTES, ULONG, ULONG64, PCWSTR]
    CreateFileMappingFromApp.restype = HANDLE
    res = CreateFileMappingFromApp(hFile, SecurityAttributes, PageProtection, MaximumSize, Name)
    return win32_to_errcheck(res, errcheck)


def MapViewOfFileFromApp(hFileMappingObject, DesiredAccess, FileOffset, NumberOfBytesToMap, errcheck: bool = True):
    MapViewOfFileFromApp = kernel32.MapViewOfFileFromApp
    MapViewOfFileFromApp.argtypes = [HANDLE, ULONG, ULONG64, SIZE_T]
    MapViewOfFileFromApp.restype = PVOID
    res = MapViewOfFileFromApp(hFileMappingObject, DesiredAccess, FileOffset, NumberOfBytesToMap)
    return win32_to_errcheck(res, errcheck)


def VirtualUnlockEx(Process, Address, Size, errcheck: bool = True):
    VirtualUnlockEx = kernel32.VirtualUnlockEx
    VirtualUnlockEx.argtypes = [HANDLE, LPVOID, SIZE_T]
    VirtualUnlockEx.restype = WINBOOL
    res = VirtualUnlockEx(Process, Address, Size)
    return win32_to_errcheck(res, errcheck)


def SetProcessValidCallTargets(hProcess, VirtualAddress, RegionSize, NumberOfOffsets, OffsetInformation, errcheck: bool = True):
    SetProcessValidCallTargets = kernel32.SetProcessValidCallTargets
    SetProcessValidCallTargets.argtypes = [HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO]
    SetProcessValidCallTargets.restype = WINBOOL
    res = SetProcessValidCallTargets(hProcess, VirtualAddress, RegionSize, NumberOfOffsets, OffsetInformation)
    return win32_to_errcheck(res, errcheck)


def SetProcessValidCallTargetsForMappedView(Process, VirtualAddress, RegionSize, NumberOfOffsets, OffsetInformation, Section, ExpectedFileOffset, errcheck: bool = True):       
    SetProcessValidCallTargetsForMappedView = kernel32.SetProcessValidCallTargetsForMappedView
    SetProcessValidCallTargetsForMappedView.argtypes = [HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO, HANDLE, ULONG64]
    SetProcessValidCallTargetsForMappedView.restype = WINBOOL
    res = SetProcessValidCallTargetsForMappedView(Process, VirtualAddress, RegionSize, NumberOfOffsets, OffsetInformation, Section, ExpectedFileOffset)
    return win32_to_errcheck(res, errcheck)


def VirtualAllocFromApp(BaseAddress, Size, AllocationType, Protection, errcheck: bool = True):
    VirtualAllocFromApp = kernel32.VirtualAllocFromApp
    VirtualAllocFromApp.argtypes = [PVOID, SIZE_T, ULONG, ]
    VirtualAllocFromApp.restype = PVOID
    res = VirtualAllocFromApp(BaseAddress, Size, AllocationType, Protection)
    return win32_to_errcheck(res, errcheck)


def VirtualProtectFromApp(lpAddress, dwSize, flNewProtect, lpflOldProtect, errcheck: bool = True):
    VirtualProtectFromApp = kernel32.VirtualProtectFromApp
    VirtualProtectFromApp.argtypes = [PVOID, SIZE_T, ULONG, PULONG]
    VirtualProtectFromApp.restype = WINBOOL
    res = VirtualProtectFromApp(lpAddress, dwSize, flNewProtect, lpflOldProtect)
    return win32_to_errcheck(res, errcheck)


def OpenFileMappingFromApp(DesiredAccess, InheritHandle, Name, errcheck: BOOL = True):
    OpenFileMappingFromApp = kernel32.OpenFileMappingFromApp
    OpenFileMappingFromApp.argtypes = [ULONG, WINBOOL, PCWSTR]
    OpenFileMappingFromApp.restype = HANDLE
    res = OpenFileMappingFromApp(DesiredAccess, InheritHandle, Name)
    return win32_to_errcheck(res, errcheck)


def VirtualAlloc2FromApp(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount, errcheck: BOOL = True):
    VirtualAlloc2FromApp = kernel32.VirtualAlloc2FromApp
    VirtualAlloc2FromApp.argtypes = [HANDLE, PVOID, SIZE_T, ULONG, ULONG, POINTER(MEM_EXTENDED_PARAMETER), ULONG]
    VirtualAlloc2FromApp.restype = PVOID
    res = VirtualAlloc2FromApp(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount)
    return win32_to_errcheck(res, errcheck)


def MapViewOfFile3FromApp(FileMapping, Process, BaseAddress, Offset, ViewSize, AllocationType, PageProtection, ExtendedParameters, ParameterCount, errcheck: BOOL = True):
    MapViewOfFile3FromApp = kernel32.MapViewOfFile3FromApp
    MapViewOfFile3FromApp.argtypes = [HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, POINTER(MEM_EXTENDED_PARAMETER), ULONG]
    MapViewOfFile3FromApp.restype = PVOID
    res = MapViewOfFile3FromApp(FileMapping, Process, BaseAddress, Offset, ViewSize, AllocationType, PageProtection, ExtendedParameters, ParameterCount)
    return win32_to_errcheck(res, errcheck)


def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect, errcheck: bool = True):
    VirtualProtect = kernel32.VirtualProtect
    VirtualProtect.argtypes = [LPVOID, SIZE_T, DWORD, PDWORD]
    VirtualProtect.restype = WINBOOL
    res = VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
    return win32_to_errcheck(res, errcheck)


FILE_MAP_EXECUTE = SECTION_MAP_EXECUTE_EXPLICIT

FILE_CACHE_MAX_HARD_ENABLE = 0x00000001
FILE_CACHE_MAX_HARD_DISABLE = 0x00000002
FILE_CACHE_MIN_HARD_ENABLE = 0x00000004
FILE_CACHE_MIN_HARD_DISABLE = 0x00000008


def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect, errcheck: bool = True):
    VirtualProtectEx = kernel32.VirtualProtectEx
    VirtualProtectEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, PDWORD]
    VirtualProtectEx.restype = WINBOOL
    res = VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)
    return win32_to_errcheck(res, errcheck)


def VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength, errcheck: bool = True):
    VirtualQueryEx = kernel32.VirtualQueryEx
    VirtualQueryEx.argtypes = [HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T]
    VirtualQueryEx.restype = SIZE_T
    res = VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength)
    return win32_to_errcheck(res, errcheck)


def ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead, errcheck: bool = True):
    ReadProcessMemory = kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
    ReadProcessMemory.restype = WINBOOL
    res = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
    return win32_to_errcheck(res, errcheck)


def WriteProcessMemory(
    hProcess: int, 
    lpBaseAddress: int, 
    lpBuffer: int, 
    nSize: Any, 
    lpNumberOfBytesWritten: int,
    errcheck: bool = True
) -> None:
    
    WriteProcessMemory = kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [
        HANDLE, 
        LPVOID, 
        LPCVOID, 
        SIZE_T, 
        SIZE_T
    ]

    WriteProcessMemory.restype = WINBOOL
    res = WriteProcessMemory(
        hProcess, 
        lpBaseAddress, 
        lpBuffer, 
        nSize, 
        lpNumberOfBytesWritten
    )

    return win32_to_errcheck(res, errcheck)


def CreateFileMapping(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, unicode: bool = True, errcheck: bool = True):
    CreateFileMapping = kernel32.CreateFileMappingW if unicode else kernel32.CreateFileMappingA
    CreateFileMapping.argtypes = [HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, (LPCWSTR if unicode else LPCSTR)]
    CreateFileMapping.restype = HANDLE
    res = CreateFileMapping(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
    return win32_to_errcheck(res, errcheck)


def OpenFileMapping(dwDesiredAccess, bInheritHandle, lpName, unicode: bool = True, errcheck: bool = True):
    OpenFileMapping = kernel32.OpenFileMappingW if unicode else kernel32.OpenFileMappingA
    OpenFileMapping.argtypes = [DWORD, WINBOOL, (LPCWSTR if unicode else LPCSTR)]
    OpenFileMapping.restype = HANDLE
    res = OpenFileMapping(dwDesiredAccess, bInheritHandle, lpName)
    return win32_to_errcheck(res, errcheck)


def MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, errcheck: bool = True):
    MapViewOfFile = kernel32.MapViewOfFile
    MapViewOfFile.argtypes = [HANDLE, DWORD, DWORD, DWORD, SIZE_T]
    MapViewOfFile.restype = LPVOID
    res = MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)
    return win32_to_errcheck(res, errcheck)


def MapViewOfFileEx(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress, errcheck: bool = True):
    MapViewOfFileEx = kernel32.MapViewOfFileEx
    MapViewOfFileEx.argtypes = [HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID]
    MapViewOfFileEx.restype = LPVOID
    res = MapViewOfFileEx(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress)
    return win32_to_errcheck(res, errcheck)


def VirtualLock(lpAddress, dwSize, errcheck: bool = True):
    VirtualLock = kernel32.VirtualLock
    VirtualLock.argtypes = [LPVOID, SIZE_T]
    VirtualLock.restype = WINBOOL
    res = VirtualLock(lpAddress, dwSize)
    return win32_to_errcheck(res, errcheck)


def VirtualUnlock(lpAddress, dwSize, errcheck: bool = True):
    VirtualUnlock = kernel32.VirtualUnlock
    VirtualUnlock.argtypes = [LPVOID, SIZE_T]
    VirtualUnlock.restype = WINBOOL
    res = VirtualUnlock(lpAddress, dwSize)
    return win32_to_errcheck(res, errcheck)


def CreateMemoryResourceNotification(NotificationType, errcheck: bool = True):
    CreateMemoryResourceNotification = kernel32.CreateMemoryResourceNotification
    CreateMemoryResourceNotification.argtypes = [MEMORY_RESOURCE_NOTIFICATION_TYPE]
    CreateMemoryResourceNotification.restype = HANDLE
    res = CreateMemoryResourceNotification(NotificationType)
    return win32_to_errcheck(res, errcheck)


def QueryMemoryResourceNotification(ResourceNotificationHandle, ResourceState, errcheck: bool = True):
    QueryMemoryResourceNotification = kernel32.QueryMemoryResourceNotification
    QueryMemoryResourceNotification.argtypes = [HANDLE, PBOOL]
    QueryMemoryResourceNotification.restype = WINBOOL
    res = QueryMemoryResourceNotification(ResourceNotificationHandle, ResourceState)
    return win32_to_errcheck(res, errcheck)


def GetSystemFileCacheSize(lpMinimumFileCacheSize, lpMaximumFileCacheSize, lpFlags, errcheck: bool = True):
    GetSystemFileCacheSize = kernel32.GetSystemFileCacheSize
    GetSystemFileCacheSize.argtypes = [PSIZE_T, PSIZE_T, PDWORD]
    GetSystemFileCacheSize.restype = WINBOOL
    res = GetSystemFileCacheSize(lpMinimumFileCacheSize, lpMaximumFileCacheSize, lpFlags)
    return win32_to_errcheck(res, errcheck)


def SetSystemFileCacheSize(MinimumFileCacheSize, MaximumFileCacheSize, Flags, errcheck: bool = True):
    SetSystemFileCacheSize = kernel32.SetSystemFileCacheSize
    SetSystemFileCacheSize.argtypes = [SIZE_T, SIZE_T, DWORD]
    SetSystemFileCacheSize.restype = WINBOOL
    res = SetSystemFileCacheSize(MinimumFileCacheSize, MaximumFileCacheSize, Flags)
    return win32_to_errcheck(res, errcheck)


def AllocateUserPhysicalPages(hProcess, NumberOfPages, PageArray, errcheck: bool = True):
    AllocateUserPhysicalPages = kernel32.AllocateUserPhysicalPages
    AllocateUserPhysicalPages.argtypes = [HANDLE, PULONG_PTR, PULONG_PTR]
    AllocateUserPhysicalPages.restype = WINBOOL
    res = AllocateUserPhysicalPages(hProcess, NumberOfPages, PageArray)
    return win32_to_errcheck(res, errcheck)


def FreeUserPhysicalPages(hProcess, NumberOfPages, PageArray, errcheck: bool = True):
    FreeUserPhysicalPages = kernel32.FreeUserPhysicalPages
    FreeUserPhysicalPages.argtypes = [HANDLE, PULONG_PTR, PULONG_PTR]
    FreeUserPhysicalPages.restype = WINBOOL
    res = FreeUserPhysicalPages(hProcess, NumberOfPages, PageArray)
    return win32_to_errcheck(res, errcheck)


def MapUserPhysicalPages(VirtualAddress, NumberOfPages, PageArray, errcheck: bool = True):
    MapUserPhysicalPages = kernel32.MapUserPhysicalPages
    MapUserPhysicalPages.argtypes = [PVOID, ULONG_PTR, PULONG_PTR]
    MapUserPhysicalPages.restype = WINBOOL
    res = MapUserPhysicalPages(VirtualAddress, NumberOfPages, PageArray)
    return win32_to_errcheck(res, errcheck)


def AllocateUserPhysicalPagesNuma(hProcess, NumberOfPages, PageArray, nndPreferred, errcheck: bool = True):
    AllocateUserPhysicalPagesNuma = kernel32.AllocateUserPhysicalPagesNuma
    AllocateUserPhysicalPagesNuma.argtypes = [HANDLE, PULONG_PTR, PULONG_PTR, DWORD]
    AllocateUserPhysicalPagesNuma.restype = WINBOOL
    res = AllocateUserPhysicalPagesNuma(hProcess, NumberOfPages, PageArray, nndPreferred)
    return win32_to_errcheck(res, errcheck)


def CreateFileMappingNuma(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, nndPreferred, unicode: bool = True, errcheck: bool = True):
    CreateFileMappingNuma = kernel32.CreateFileMappingNumaW if unicode else kernel32.CreateFileMappingNumaA
    CreateFileMappingNuma.argtypes = [HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, (LPCWSTR if unicode else LPCSTR), DWORD]
    CreateFileMappingNuma.restype = HANDLE
    res = CreateFileMappingNuma(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, nndPreferred)
    return win32_to_errcheck(res, errcheck)


def VirtualAllocExNuma(hProcess, lpAddress, dwSize, flAllocationType, flProtect, nndPreferred, errcheck: bool = True):
    VirtualAllocExNuma = kernel32.VirtualAllocExNuma
    VirtualAllocExNuma.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD]
    VirtualAllocExNuma.restype = LPVOID
    res = VirtualAllocExNuma(hProcess, lpAddress, dwSize, flAllocationType, flProtect, nndPreferred)
    return win32_to_errcheck(res, errcheck)


def GetMemoryErrorHandlingCapabilities(Capabilities, errcheck: bool = True):
    GetMemoryErrorHandlingCapabilities = kernel32.GetMemoryErrorHandlingCapabilities
    GetMemoryErrorHandlingCapabilities.argtypes = [PULONG]
    GetMemoryErrorHandlingCapabilities.restype = WINBOOL
    res = GetMemoryErrorHandlingCapabilities(Capabilities)
    return win32_to_errcheck(res, errcheck)


def PrefetchVirtualMemory(hProcess, NumberOfEntries, VirtualAddresses, Flags, errcheck: bool = True):
    PrefetchVirtualMemory = kernel32.PrefetchVirtualMemory
    PrefetchVirtualMemory.argtypes = [HANDLE, ULONG_PTR, PWIN32_MEMORY_RANGE_ENTRY, ULONG]
    PrefetchVirtualMemory.restype = WINBOOL
    res = PrefetchVirtualMemory(hProcess, NumberOfEntries, VirtualAddresses, Flags)
    return win32_to_errcheck(res, errcheck)


MEHC_PATROL_SCRUBBER_PRESENT = 0x1

BAD_MEMORY_CALLBACK_ROUTINE = WINAPI(VOID, VOID)
PBAD_MEMORY_CALLBACK_ROUTINE = POINTER(BAD_MEMORY_CALLBACK_ROUTINE)


def RegisterBadMemoryNotification(Callback, errcheck: bool = True):
    RegisterBadMemoryNotification = kernel32.RegisterBadMemoryNotification
    RegisterBadMemoryNotification.argtypes = [PBAD_MEMORY_CALLBACK_ROUTINE]
    RegisterBadMemoryNotification.restype = PVOID
    res = RegisterBadMemoryNotification(Callback)
    return win32_to_errcheck(res, errcheck)


def UnregisterBadMemoryNotification(RegistrationHandle, errcheck: bool = True):
    UnregisterBadMemoryNotification = kernel32.UnregisterBadMemoryNotification
    UnregisterBadMemoryNotification.argtypes = [PVOID]
    UnregisterBadMemoryNotification.restype = WINBOOL
    res = UnregisterBadMemoryNotification(RegistrationHandle)
    return win32_to_errcheck(res, errcheck)


MemoryRegionInfo = 0

class WIN32_MEMORY_INFORMATION_CLASS(enum.IntFlag):
    MemoryRegionInfo = 0

class WIN32_MEMORY_REGION_INFORMATION(Structure):
    class Anonymous_union(Union):
        class Anonymous_LittleEndianStructure(LittleEndianStructure):
            _fields_ = [('Private', ULONG, 1),
                        ('MappedDataFile', ULONG, 1),
                        ('MappedImage', ULONG, 1),
                        ('MappedPageFile', ULONG, 1),
                        ('MappedPhysical', ULONG, 1),
                        ('DirectMapped', ULONG, 1),
                        ('Reserved', ULONG, 26)
            ]
        
        _anonymous_ = ['Anonymous_LittleEndianStructure']
        _fields_ = [('Anonymous_LittleEndianStructure', Anonymous_LittleEndianStructure)]
    
    _anonymous_ = ['Anonymous_union']
    _fields_ = [('AllocationBase', PVOID),
                ('AllocationProtect', ULONG),
                ('Anonymous_union', Anonymous_union),
                ('RegionSize', SIZE_T),
                ('CommitSize', SIZE_T)
    ]


def QueryVirtualMemoryInformation(Process, VirtualAddress, MemoryInformationClass, MemoryInformation, MemoryInformationSize, ReturnSize, errcheck: bool = True):
    QueryVirtualMemoryInformation = kernel32.QueryVirtualMemoryInformation
    QueryVirtualMemoryInformation.argtypes = [HANDLE, POINTER(VOID), WIN32_MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T]
    QueryVirtualMemoryInformation.restype = WINBOOL
    res = QueryVirtualMemoryInformation(Process, VirtualAddress, MemoryInformationClass, MemoryInformation, MemoryInformationSize, ReturnSize)
    return win32_to_errcheck(res, errcheck)


def MapViewOfFileNuma2(FileMappingHandle, ProcessHandle, Offset, BaseAddress, ViewSize, AllocationType, PageProtection, PreferredNode, errcheck: bool = True):
    MapViewOfFileNuma2 = kernel32.MapViewOfFileNuma2
    MapViewOfFileNuma2.argtypes = [HANDLE, HANDLE, ULONG64, PVOID, SIZE_T, ULONG, ULONG, ULONG]
    MapViewOfFileNuma2.restype = PVOID
    res = MapViewOfFileNuma2(FileMappingHandle, ProcessHandle, Offset, BaseAddress, ViewSize, AllocationType, PageProtection, PreferredNode)
    return win32_to_errcheck(res, errcheck)


def MapViewOfFile2(FileMappingHandle, ProcessHandle, Offset, BaseAddress, ViewSize, AllocationType, PageProtection, errcheck: bool = True):
    MapViewOfFile2 = kernel32.MapViewOfFile2
    MapViewOfFile2.argtypes = [HANDLE, HANDLE, ULONG64, PVOID, SIZE_T, ULONG, ULONG]
    MapViewOfFile2.restype = PVOID
    res = MapViewOfFile2(FileMappingHandle, ProcessHandle, Offset, BaseAddress, ViewSize, AllocationType, PageProtection)
    return win32_to_errcheck(res, errcheck)


def VirtualAlloc2(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount, errcheck: bool = True):
    VirtualAlloc2 = kernel32.VirtualAlloc2
    VirtualAlloc2.argtypes = [HANDLE, PVOID, SIZE_T, ULONG, ULONG, POINTER(MEM_EXTENDED_PARAMETER), ULONG]
    VirtualAlloc2.restype = PVOID
    res = VirtualAlloc2(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount)
    return win32_to_errcheck(res, errcheck)


def MapViewOfFile3(FileMapping, Process, BaseAddress, Offset, ViewSize, AllocationType, PageProtection, ExtendedParameters, ParameterCount, errcheck: bool = True):
    MapViewOfFile3 = kernel32.MapViewOfFile3
    MapViewOfFile3.argtypes = [HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, POINTER(MEM_EXTENDED_PARAMETER), ULONG]
    MapViewOfFile3.restype = PVOID
    res = MapViewOfFile3(FileMapping, Process, BaseAddress, Offset, ViewSize, AllocationType, PageProtection, ExtendedParameters, ParameterCount)
    return win32_to_errcheck(res, errcheck)


def CreateFileMapping2(File, SecurityAttributes, DesiredAccess, PageProtection, AllocationAttributes, MaximumSize, Name, ExtendedParameters, ParameterCount, errcheck: bool = True):
    CreateFileMapping2 = kernel32.CreateFileMapping2
    CreateFileMapping2.argtypes = [HANDLE, POINTER(SECURITY_ATTRIBUTES), ULONG, ULONG, ULONG, ULONG64, PCWSTR, POINTER(MEM_EXTENDED_PARAMETER), ULONG]
    CreateFileMapping2.restype = HANDLE
    res = CreateFileMapping2(File, SecurityAttributes, DesiredAccess, PageProtection, AllocationAttributes, MaximumSize, Name, ExtendedParameters, ParameterCount)
    return win32_to_errcheck(res, errcheck)


def GetLargePageMinimum(errcheck: bool = True):
    GetLargePageMinimum = kernel32.GetLargePageMinimum
    GetLargePageMinimum.restype = SIZE_T
    res = GetLargePageMinimum()
    return win32_to_errcheck(res, errcheck)


def GetProcessWorkingSetSizeEx(hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags, errcheck: bool = True):
    GetProcessWorkingSetSizeEx = kernel32.GetProcessWorkingSetSizeEx
    GetProcessWorkingSetSizeEx.argtypes = [HANDLE, PSIZE_T, PSIZE_T, PDWORD]
    GetProcessWorkingSetSizeEx.restype = WINBOOL
    res = GetProcessWorkingSetSizeEx(hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags)
    return win32_to_errcheck(res, errcheck)


def SetProcessWorkingSetSizeEx(hProcess, dwMinimumWorkingSetSize, dwMaximumWorkingSetSize, Flags, errcheck: bool = True):
    SetProcessWorkingSetSizeEx = kernel32.SetProcessWorkingSetSizeEx
    SetProcessWorkingSetSizeEx.argtypes = [HANDLE, SIZE_T, SIZE_T, DWORD]
    SetProcessWorkingSetSizeEx.restype = WINBOOL
    res = SetProcessWorkingSetSizeEx(hProcess, dwMinimumWorkingSetSize, dwMaximumWorkingSetSize, Flags)
    return win32_to_errcheck(res, errcheck)


def GetWriteWatch(dwFlags, lpBaseAddress, dwRegionSize, lpAddresses, lpdwCount, lpdwGranularity, errcheck: bool = True):
    GetWriteWatch = kernel32.GetWriteWatch
    GetWriteWatch.argtypes = [DWORD, PVOID, SIZE_T, POINTER(PVOID), POINTER(ULONG_PTR), LPDWORD]
    GetWriteWatch.restype = UINT
    res = GetWriteWatch(dwFlags, lpBaseAddress, dwRegionSize, lpAddresses, lpdwCount, lpdwGranularity)
    return win32_to_errcheck(res, errcheck)


def ResetWriteWatch(lpBaseAddress, dwRegionSize, errcheck: bool = True):
    ResetWriteWatch = kernel32.ResetWriteWatch
    ResetWriteWatch.argtypes = [LPVOID, SIZE_T]
    ResetWriteWatch.restype = UINT
    res = ResetWriteWatch(lpBaseAddress, dwRegionSize)
    return win32_to_errcheck(res, errcheck)


def VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType, errcheck: bool = True):
    VirtualFreeEx = kernel32.VirtualFreeEx
    VirtualFreeEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD]
    VirtualFreeEx.restype = WINBOOL
    res = VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType)
    return win32_to_errcheck(res, errcheck)


VmOfferPriorityVeryLow = 1
VmOfferPriorityLow = 2
VmOfferPriorityBelowNormal = 3
VmOfferPriorityNormal = 4

class _OFFER_PRIORITY(enum.IntFlag):
    VmOfferPriorityVeryLow = 1
    VmOfferPriorityLow = 2
    VmOfferPriorityBelowNormal = 3
    VmOfferPriorityNormal = 4

OFFER_PRIORITY = _OFFER_PRIORITY

def DiscardVirtualMemory(VirtualAddress, Size, errcheck: bool = True):
    DiscardVirtualMemory = kernel32.DiscardVirtualMemory
    DiscardVirtualMemory.argtypes = [PVOID, SIZE_T]
    DiscardVirtualMemory.restype = DWORD
    res = DiscardVirtualMemory(VirtualAddress, Size)
    return win32_to_errcheck(res, errcheck)


def OfferVirtualMemory(VirtualAddress, Size, Priority, errcheck: bool = True):
    OfferVirtualMemory = kernel32.OfferVirtualMemory
    OfferVirtualMemory.argtypes = [PVOID, SIZE_T, OFFER_PRIORITY]
    OfferVirtualMemory.restype = DWORD
    res = OfferVirtualMemory(VirtualAddress, Size, Priority)
    return win32_to_errcheck(res, errcheck)


def ReclaimVirtualMemory(VirtualAddress, Size, errcheck: bool = True):
    ReclaimVirtualMemory = kernel32.ReclaimVirtualMemory
    ReclaimVirtualMemory.argtypes = [PVOID, SIZE_T]
    ReclaimVirtualMemory.restype = DWORD
    res = ReclaimVirtualMemory(VirtualAddress, Size)
    return win32_to_errcheck(res, errcheck)


def UnmapViewOfFileEx(BaseAddress, UnmapFlags, errcheck: bool = True):
    UnmapViewOfFileEx = kernel32.UnmapViewOfFileEx
    UnmapViewOfFileEx.argtypes = [PVOID, ULONG]
    UnmapViewOfFileEx.restype = WINBOOL
    res = UnmapViewOfFileEx(BaseAddress, UnmapFlags)
    return win32_to_errcheck(res, errcheck)