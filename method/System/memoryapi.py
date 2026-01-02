# coding = 'utf-8'
# memoryapi.h

import enum
from typing import Any
from method.System.sdkddkver import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck, hresult_to_errcheck

_WIN32_WINNT = WIN32_WINNT
_WIN32_WINNT_WIN8 = 0x0602
_WIN32_WINNT_WIN10 = 0x0A00

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

if _WIN32_WINNT >= _WIN32_WINNT_WIN8:
    class _WIN32_MEMORY_RANGE_ENTRY(Structure):
        _fields_ = [('VirtualAddress', PVOID),
                    ('NumberOfBytes', SIZE_T)
        ]

    WIN32_MEMORY_RANGE_ENTRY = _WIN32_MEMORY_RANGE_ENTRY
    PWIN32_MEMORY_RANGE_ENTRY = POINTER(WIN32_MEMORY_RANGE_ENTRY)


def VirtualFree(lpAddress, dwSize, dwFreeType, errcheck: bool = True):
    VirtualFree = Kernel32.VirtualFree
    res = VirtualFree(lpAddress, dwSize, dwFreeType)
    return win32_to_errcheck(res, errcheck)    

def VirtualAlloc(lpAddress: int, dwSize: int, flAllocationType: int, flProtect: int, errcheck: bool = True) -> int:
    VirtualAlloc = Kernel32.VirtualAlloc
    VirtualAlloc.restype = VOID
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
    
    VirtualAllocEx = Kernel32.VirtualAllocEx
    VirtualAllocEx.restype = VOID
    res = VirtualAllocEx(hProcess, 
                         lpAddress, 
                         dwSize, 
                         flAllocationType, 
                         flProtect
    )

    return win32_to_errcheck(res, errcheck)    


FILE_MAP_WRITE = SECTION_MAP_WRITE
FILE_MAP_READ = SECTION_MAP_READ
FILE_MAP_ALL_ACCESS = SECTION_ALL_ACCESS
FILE_MAP_COPY = 0x1
FILE_MAP_RESERVE = 0x80000000
FILE_MAP_TARGETS_INVALID = 0x40000000
FILE_MAP_LARGE_PAGES = 0x20000000


def VirtualQuery(lpAddress, lpBuffer, dwLength, errcheck: bool = True):
    VirtualQuery = Kernel32.VirtualQuery
    res = VirtualQuery(lpAddress, lpBuffer, dwLength)
    return win32_to_errcheck(res, errcheck)

def FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush, errcheck: bool = True):
    FlushViewOfFile = Kernel32.FlushViewOfFile
    res = FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush)
    return win32_to_errcheck(res, errcheck)    

def UnmapViewOfFile(lpBaseAddress, errcheck: bool = True):
    UnmapViewOfFile = Kernel32.UnmapViewOfFile
    res = UnmapViewOfFile(lpBaseAddress)
    return win32_to_errcheck(res, errcheck)    

def UnmapViewOfFile2(Process, BaseAddress, UnmapFlags, errcheck: bool = True):
    UnmapViewOfFile2 = Kernel32.UnmapViewOfFile2
    res = UnmapViewOfFile2(Process, BaseAddress, UnmapFlags)
    return win32_to_errcheck(res, errcheck)    

def CreateFileMappingFromApp(hFile, SecurityAttributes, PageProtection, MaximumSize, Name, errcheck: bool = True):
    CreateFileMappingFromApp = Kernel32.CreateFileMappingFromApp
    res = CreateFileMappingFromApp(hFile, SecurityAttributes, PageProtection, MaximumSize, Name)
    return win32_to_errcheck(res, errcheck)    


def MapViewOfFileFromApp(hFileMappingObject, DesiredAccess, FileOffset, NumberOfBytesToMap, errcheck: bool = True):
    MapViewOfFileFromApp = Kernel32.MapViewOfFileFromApp
    MapViewOfFileFromApp.restype = PVOID
    res = MapViewOfFileFromApp(hFileMappingObject, DesiredAccess, FileOffset, NumberOfBytesToMap)
    return win32_to_errcheck(res, errcheck)    


def VirtualUnlockEx(Process, Address, Size, errcheck: bool = True):
    VirtualUnlockEx = Kernel32.VirtualUnlockEx
    res = VirtualUnlockEx(Process, Address, Size)
    return win32_to_errcheck(res, errcheck)    

if _WIN32_WINNT >= _WIN32_WINNT_WIN10:
    def SetProcessValidCallTargets(
        hProcess, 
        VirtualAddress, 
        RegionSize, 
        NumberOfOffsets, 
        OffsetInformation,
        errcheck: bool = True
    ):
        
        SetProcessValidCallTargets = Kernel32.SetProcessValidCallTargets
        res = SetProcessValidCallTargets(
            hProcess, 
            VirtualAddress, 
            RegionSize, 
            NumberOfOffsets, 
            OffsetInformation
        )

        return win32_to_errcheck(res, errcheck)        


    def SetProcessValidCallTargetsForMappedView(
        Process, 
        VirtualAddress, 
        RegionSize, 
        NumberOfOffsets, 
        OffsetInformation, 
        Section, 
        ExpectedFileOffset,
        errcheck: bool = True
    ):
        
        SetProcessValidCallTargetsForMappedView = Kernel32.SetProcessValidCallTargetsForMappedView
        res = SetProcessValidCallTargetsForMappedView(
            Process, 
            VirtualAddress, 
            RegionSize, 
            NumberOfOffsets, 
            OffsetInformation, 
            Section, 
            ExpectedFileOffset
        )

        return win32_to_errcheck(res, errcheck)        

    def VirtualAllocFromApp(BaseAddress, Size, AllocationType, Protection, errcheck: bool = True):
        VirtualAllocFromApp = Kernel32.VirtualAllocFromApp
        VirtualAllocFromApp.restype = PVOID
        res = VirtualAllocFromApp(BaseAddress, Size, AllocationType, Protection)
        return win32_to_errcheck(res, errcheck)        


    def VirtualProtectFromApp(lpAddress, dwSize, flNewProtect, lpflOldProtect, errcheck: bool = True):
        VirtualProtectFromApp = Kernel32.VirtualProtectFromApp
        res = VirtualProtectFromApp(lpAddress, dwSize, flNewProtect, lpflOldProtect)
        return win32_to_errcheck(res, errcheck)        

    def OpenFileMappingFromApp(DesiredAccess, InheritHandle, Name, errcheck: bool = True):
        OpenFileMappingFromApp = Kernel32.OpenFileMappingFromApp
        res = OpenFileMappingFromApp(DesiredAccess, InheritHandle, Name)
        return win32_to_errcheck(res, errcheck)        
    

if NTDDI_VERSION >= NTDDI_WIN10_RS4:
    def VirtualAlloc2FromApp(
        Process, 
        BaseAddress, 
        Size, 
        AllocationType, 
        PageProtection, 
        ExtendedParameters, 
        ParameterCount,
        errcheck: bool = True
    ):
        
        VirtualAlloc2FromApp = Kernel32.VirtualAlloc2FromApp
        VirtualAlloc2FromApp.restype = PVOID
        res = VirtualAlloc2FromApp(
            Process, 
            BaseAddress, 
            Size, 
            AllocationType, 
            PageProtection, 
            ExtendedParameters, 
            ParameterCount
        )

        return win32_to_errcheck(res, errcheck)        


    def MapViewOfFile3FromApp(
        FileMapping, 
        Process, 
        BaseAddress, 
        Offset, 
        ViewSize, 
        AllocationType, 
        PageProtection, 
        ExtendedParameters, 
        ParameterCount,
        errcheck: bool = True
    ):
        
        MapViewOfFile3FromApp = Kernel32.MapViewOfFile3FromApp
        MapViewOfFile3FromApp.restype = PVOID
        res = MapViewOfFile3FromApp(
            FileMapping, 
            Process, 
            BaseAddress, 
            Offset, 
            ViewSize, 
            AllocationType, 
            PageProtection, 
            ExtendedParameters, 
            ParameterCount
        )

        return win32_to_errcheck(res, errcheck)        


def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect, errcheck: bool = True):
    VirtualProtect = Kernel32.VirtualProtect
    res = VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
    return win32_to_errcheck(res, errcheck)

FILE_MAP_EXECUTE = SECTION_MAP_EXECUTE_EXPLICIT

FILE_CACHE_MAX_HARD_ENABLE = 0x00000001
FILE_CACHE_MAX_HARD_DISABLE = 0x00000002
FILE_CACHE_MIN_HARD_ENABLE = 0x00000004
FILE_CACHE_MIN_HARD_DISABLE = 0x00000008


def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect, errcheck: bool = True):
    VirtualProtectEx = Kernel32.VirtualProtectEx
    res = VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)
    return win32_to_errcheck(res, errcheck)    

def VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength, errcheck: bool = True):
    VirtualQueryEx = Kernel32.VirtualQueryEx
    res = VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength)
    return win32_to_errcheck(res, errcheck)    


def ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead, errcheck: bool = True):
    ReadProcessMemory = Kernel32.ReadProcessMemory
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
    
    WriteProcessMemory = Kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [HANDLE, 
                                   LPVOID, 
                                   LPCVOID, 
                                   SIZE_T, 
                                   SIZE_T
    ]

    res = WriteProcessMemory(
        hProcess, 
        lpBaseAddress, 
        lpBuffer, 
        nSize, 
        lpNumberOfBytesWritten
    )

    return win32_to_errcheck(res, errcheck)

def CreateFileMapping(
    hFile, 
    lpFileMappingAttributes, 
    flProtect, 
    dwMaximumSizeHigh, 
    dwMaximumSizeLow, 
    lpName, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    CreateFileMapping = Kernel32.CreateFileMappingW if unicode else Kernel32.CreateFileMappingA
    res = CreateFileMapping(
        hFile, 
        lpFileMappingAttributes, 
        flProtect, 
        dwMaximumSizeHigh, 
        dwMaximumSizeLow, 
        lpName
    )

    return win32_to_errcheck(res, errcheck)    


def OpenFileMapping(dwDesiredAccess, bInheritHandle, lpName, unicode: bool = True, errcheck: bool = True):
    OpenFileMapping = Kernel32.OpenFileMappingW if unicode else Kernel32.OpenFileMappingA
    res = OpenFileMapping(dwDesiredAccess, bInheritHandle, lpName)
    return win32_to_errcheck(res, errcheck)    


def MapViewOfFile(
    hFileMappingObject, 
    dwDesiredAccess, 
    dwFileOffsetHigh, 
    dwFileOffsetLow, 
    dwNumberOfBytesToMap,
    errcheck: bool = True
):
    
    MapViewOfFile = Kernel32.MapViewOfFile
    MapViewOfFile.restype = LPVOID
    res = MapViewOfFile(
        hFileMappingObject, 
        dwDesiredAccess, 
        dwFileOffsetHigh, 
        dwFileOffsetLow, 
        dwNumberOfBytesToMap
    )

    return win32_to_errcheck(res, errcheck)    


def MapViewOfFileEx(
    hFileMappingObject, 
    dwDesiredAccess, 
    dwFileOffsetHigh, 
    dwFileOffsetLow, 
    dwNumberOfBytesToMap, 
    lpBaseAddress,
    errcheck: bool = True
):
    
    MapViewOfFileEx = Kernel32.MapViewOfFileEx
    MapViewOfFileEx.restype = LPVOID
    res = MapViewOfFileEx(
        hFileMappingObject, 
        dwDesiredAccess, 
        dwFileOffsetHigh, 
        dwFileOffsetLow, 
        dwNumberOfBytesToMap, 
        lpBaseAddress
    )

    return win32_to_errcheck(res, errcheck)    

def VirtualLock(lpAddress, dwSize, errcheck: bool = True):
    VirtualLock = Kernel32.VirtualLock
    res = VirtualLock(lpAddress, dwSize)
    return win32_to_errcheck(res, errcheck)    

def VirtualUnlock(lpAddress, dwSize, errcheck: bool = True):
    VirtualUnlock = Kernel32.VirtualLock
    res = VirtualUnlock(lpAddress, dwSize)
    return win32_to_errcheck(res, errcheck)    

def CreateMemoryResourceNotification(NotificationType, errcheck: bool = True):
    CreateMemoryResourceNotification = Kernel32.CreateMemoryResourceNotification
    res = CreateMemoryResourceNotification(NotificationType)
    return win32_to_errcheck(res, errcheck)    


def QueryMemoryResourceNotification(ResourceNotificationHandle, ResourceState, errcheck: bool = True):
    QueryMemoryResourceNotification = Kernel32.QueryMemoryResourceNotification
    res = QueryMemoryResourceNotification(ResourceNotificationHandle, ResourceState)
    return win32_to_errcheck(res, errcheck)    


def GetSystemFileCacheSize(lpMinimumFileCacheSize, lpMaximumFileCacheSize, lpFlags, errcheck: bool = True):
    GetSystemFileCacheSize = Kernel32.GetSystemFileCacheSize
    res = GetSystemFileCacheSize(lpMinimumFileCacheSize, lpMaximumFileCacheSize, lpFlags)
    return win32_to_errcheck(res, errcheck)    


def SetSystemFileCacheSize(MinimumFileCacheSize, MaximumFileCacheSize, Flags, errcheck: bool = True):
    SetSystemFileCacheSize = Kernel32.SetSystemFileCacheSize
    res = SetSystemFileCacheSize(MinimumFileCacheSize, MaximumFileCacheSize, Flags)
    return win32_to_errcheck(res, errcheck)    


def AllocateUserPhysicalPages(hProcess, NumberOfPages, PageArray, errcheck: bool = True):
    AllocateUserPhysicalPages = Kernel32.AllocateUserPhysicalPages
    res = AllocateUserPhysicalPages(hProcess, NumberOfPages, PageArray)
    return win32_to_errcheck(res, errcheck)    


def FreeUserPhysicalPages(hProcess, NumberOfPages, PageArray, errcheck: bool = True):
    FreeUserPhysicalPages = Kernel32.FreeUserPhysicalPages
    res = FreeUserPhysicalPages(hProcess, NumberOfPages, PageArray)
    return win32_to_errcheck(res, errcheck)    


def MapUserPhysicalPages(VirtualAddress, NumberOfPages, PageArray, errcheck: bool = True):
    MapUserPhysicalPages = Kernel32.MapUserPhysicalPages
    res = MapUserPhysicalPages(VirtualAddress, NumberOfPages, PageArray)
    return win32_to_errcheck(res, errcheck)    


def AllocateUserPhysicalPagesNuma(hProcess, NumberOfPages, PageArray, nndPreferred, errcheck: bool = True):
    AllocateUserPhysicalPagesNuma = Kernel32.AllocateUserPhysicalPagesNuma
    res = AllocateUserPhysicalPagesNuma(hProcess, NumberOfPages, PageArray, nndPreferred)
    return win32_to_errcheck(res, errcheck)    


def CreateFileMappingNuma(
    hFile, 
    lpFileMappingAttributes, 
    flProtect, 
    dwMaximumSizeHigh, 
    dwMaximumSizeLow, 
    lpName, 
    nndPreferred, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    CreateFileMappingNuma = Kernel32.CreateFileMappingNumaW if unicode else Kernel32.CreateFileMappingNumaA
    res = CreateFileMappingNuma(
        hFile, 
        lpFileMappingAttributes, 
        flProtect, 
        dwMaximumSizeHigh, 
        dwMaximumSizeLow, 
        lpName, 
        nndPreferred
    )

    return win32_to_errcheck(res, errcheck)    


def VirtualAllocExNuma(hProcess, lpAddress, dwSize, flAllocationType, flProtect, nndPreferred, errcheck: bool = True):
    VirtualAllocExNuma = Kernel32.VirtualAllocExNuma
    VirtualAllocExNuma.restype = LPVOID
    res = VirtualAllocExNuma(hProcess, lpAddress, dwSize, flAllocationType, flProtect, nndPreferred)
    return win32_to_errcheck(res, errcheck)    

if _WIN32_WINNT >= _WIN32_WINNT_WIN8:
    MEHC_PATROL_SCRUBBER_PRESENT = 0x1

    def GetMemoryErrorHandlingCapabilities(Capabilities, errcheck: bool = True):
        GetMemoryErrorHandlingCapabilities = Kernel32.GetMemoryErrorHandlingCapabilities
        res = GetMemoryErrorHandlingCapabilities(Capabilities)
        return win32_to_errcheck(res, errcheck)        

    def PrefetchVirtualMemory(hProcess, NumberOfEntries, VirtualAddresses, Flags, errcheck: bool = True):
        PrefetchVirtualMemory = Kernel32.PrefetchVirtualMemory
        res = PrefetchVirtualMemory(hProcess, NumberOfEntries, VirtualAddresses, Flags)
        return win32_to_errcheck(res, errcheck)        

    BAD_MEMORY_CALLBACK_ROUTINE = WINAPI(VOID, VOID)
    PBAD_MEMORY_CALLBACK_ROUTINE = POINTER(BAD_MEMORY_CALLBACK_ROUTINE)

    def RegisterBadMemoryNotification(Callback, errcheck: bool = True):
        RegisterBadMemoryNotification = Kernel32.RegisterBadMemoryNotification
        RegisterBadMemoryNotification.restype = PVOID
        res = RegisterBadMemoryNotification(Callback)
        return win32_to_errcheck(res, errcheck)        


    def UnregisterBadMemoryNotification(RegistrationHandle, errcheck: bool = True):
        UnregisterBadMemoryNotification = Kernel32.UnregisterBadMemoryNotification
        res = UnregisterBadMemoryNotification(RegistrationHandle)
        return win32_to_errcheck(res, errcheck)    

if NTDDI_VERSION >= NTDDI_WIN10_RS1:
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


    def QueryVirtualMemoryInformation(
        Process, 
        VirtualAddress, 
        MemoryInformationClass, 
        MemoryInformation, 
        MemoryInformationSize, 
        ReturnSize,
        errcheck: bool = True
    ):
        
        QueryVirtualMemoryInformation = Kernel32.QueryVirtualMemoryInformation
        res = QueryVirtualMemoryInformation(
            Process, 
            VirtualAddress, 
            MemoryInformationClass, 
            MemoryInformation, 
            MemoryInformationSize, 
            ReturnSize
        )

        return win32_to_errcheck(res, errcheck)    

if NTDDI_VERSION >= NTDDI_WIN10_RS2:
    def MapViewOfFileNuma2(
        FileMappingHandle, 
        ProcessHandle, 
        Offset, 
        BaseAddress, 
        ViewSize, 
        AllocationType, 
        PageProtection, 
        PreferredNode,
        errcheck: bool = True
    ):
        
        MapViewOfFileNuma2 = Kernel32.MapViewOfFileNuma2
        MapViewOfFileNuma2.restype = PVOID
        res = MapViewOfFileNuma2(
            FileMappingHandle, 
            ProcessHandle, 
            Offset, 
            BaseAddress, 
            ViewSize, 
            AllocationType, 
            PageProtection, 
            PreferredNode
        )

        return win32_to_errcheck(res, errcheck)


    def MapViewOfFile2(
        FileMappingHandle, 
        ProcessHandle, 
        Offset, 
        BaseAddress, 
        ViewSize, 
        AllocationType, 
        PageProtection,
        errcheck: bool = True
    ):
        
        MapViewOfFile2 = Kernel32.MapViewOfFile2
        MapViewOfFile2.restype = PVOID
        res = MapViewOfFile2(
            FileMappingHandle, 
            ProcessHandle, 
            Offset, 
            BaseAddress, 
            ViewSize, 
            AllocationType, 
            PageProtection
        )

        return win32_to_errcheck(res, errcheck)        

if NTDDI_VERSION >= NTDDI_WIN10_RS4:
    def VirtualAlloc2(
        Process, 
        BaseAddress, 
        Size, 
        AllocationType, 
        PageProtection, 
        ExtendedParameters, 
        ParameterCount,
        errcheck: bool = True
    ):
        
        VirtualAlloc2 = Kernel32.VirtualAlloc2
        VirtualAlloc2.restype = PVOID
        res = VirtualAlloc2(
            Process, 
            BaseAddress, 
            Size, 
            AllocationType, 
            PageProtection, 
            ExtendedParameters, 
            ParameterCount
        )

        return win32_to_errcheck(res, errcheck)        


    def MapViewOfFile3(
        FileMapping, 
        Process, 
        BaseAddress, 
        Offset, 
        ViewSize, 
        AllocationType, 
        PageProtection, 
        ExtendedParameters, 
        ParameterCount,
        errcheck: bool = True
    ):
        
        MapViewOfFile3 = Kernel32.MapViewOfFile3
        MapViewOfFile3.restype = PVOID
        res = MapViewOfFile3(
            FileMapping, 
            Process, 
            BaseAddress, 
            Offset, 
            ViewSize, 
            AllocationType, 
            PageProtection, 
            ExtendedParameters, 
            ParameterCount
        )

        return win32_to_errcheck(res, errcheck)        


if NTDDI_VERSION >= NTDDI_WIN10_RS5:
    def CreateFileMapping2(
        File, 
        SecurityAttributes, 
        DesiredAccess, 
        PageProtection, 
        AllocationAttributes, 
        MaximumSize, 
        Name, 
        ExtendedParameters, 
        ParameterCount,
        errcheck: bool = True
    ):
        
        CreateFileMapping2 = Kernel32.CreateFileMapping2
        CreateFileMapping2.restype = HANDLE
        res = CreateFileMapping2(
            File, 
            SecurityAttributes, 
            DesiredAccess, 
            PageProtection, 
            AllocationAttributes, 
            MaximumSize, 
            Name, 
            ExtendedParameters, 
            ParameterCount
        )
        
        return win32_to_errcheck(res, errcheck)        


def GetLargePageMinimum():
    GetLargePageMinimum = Kernel32.GetLargePageMinimum
    return GetLargePageMinimum()


def GetProcessWorkingSetSizeEx(hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags, errcheck: bool = True):
    GetProcessWorkingSetSizeEx = Kernel32.GetProcessWorkingSetSizeEx
    res = GetProcessWorkingSetSizeEx(hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags)
    return win32_to_errcheck(res, errcheck)    

def SetProcessWorkingSetSizeEx(hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags, errcheck: bool = True):
    SetProcessWorkingSetSizeEx = Kernel32.SetProcessWorkingSetSizeEx
    res = SetProcessWorkingSetSizeEx(hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags)
    return win32_to_errcheck(res, errcheck)    

def GetWriteWatch(dwFlags, lpBaseAddress, dwRegionSize, lpAddresses, lpdwCount, lpdwGranularity, errcheck: bool = True):
    GetWriteWatch = Kernel32.GetWriteWatch
    GetWriteWatch.restype = UINT
    res = GetWriteWatch(dwFlags, lpBaseAddress, dwRegionSize, lpAddresses, lpdwCount, lpdwGranularity)
    return win32_to_errcheck(res, errcheck)    

def ResetWriteWatch(lpBaseAddress, dwRegionSize, errcheck: bool = True):
    ResetWriteWatch = Kernel32.ResetWriteWatch
    ResetWriteWatch.restype = UINT
    res = ResetWriteWatch(lpBaseAddress, dwRegionSize)
    return win32_to_errcheck(res, errcheck)    


def VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType, errcheck: bool = True):
    VirtualFreeEx = Kernel32.VirtualFreeEx
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
    DiscardVirtualMemory = Kernel32.DiscardVirtualMemory
    DiscardVirtualMemory.restype = DWORD
    res = DiscardVirtualMemory(VirtualAddress, Size)
    return hresult_to_errcheck(res, errcheck)

def OfferVirtualMemory(VirtualAddress, Size, Priority, errcheck: bool = True):
    OfferVirtualMemory = Kernel32.OfferVirtualMemory
    OfferVirtualMemory.restype = DWORD
    res = OfferVirtualMemory(VirtualAddress, Size, Priority)
    return hresult_to_errcheck(res, errcheck)    

def ReclaimVirtualMemory(VirtualAddress, Size, errcheck: bool = True):
    ReclaimVirtualMemory = Kernel32.ReclaimVirtualMemory
    res = ReclaimVirtualMemory(VirtualAddress, Size)
    return hresult_to_errcheck(res, errcheck)    

if _WIN32_WINNT >= _WIN32_WINNT_WIN8:
    def UnmapViewOfFileEx(BaseAddress, UnmapFlags, errcheck: bool = True):
        UnmapViewOfFileEx = Kernel32.UnmapViewOfFileEx
        res = UnmapViewOfFileEx(BaseAddress, UnmapFlags)
        return win32_to_errcheck(res, errcheck)        

