# coding = 'utf-8'
# memoryapi.h

import enum
from typing import Any
from ctypes import Structure, LittleEndianStructure, Union, POINTER, WinError

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


def VirtualFree(lpAddress, dwSize, dwFreeType):
    VirtualFree = Kernel32.VirtualFree
    res = VirtualFree(lpAddress, dwSize, dwFreeType)
    if not res:
        raise WinError(GetLastError())
    

def VirtualAlloc(lpAddress: int, dwSize: int, flAllocationType: int, flProtect: int) -> int:
    VirtualAlloc = Kernel32.VirtualAlloc
    VirtualAlloc.restype = VOID
    res = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
    if not res:
        raise WinError(GetLastError())
    return res


def VirtualAllocEx(hProcess: int, 
                   lpAddress: int, 
                   dwSize: int, 
                   flAllocationType: int, 
                   flProtect: int) -> int:
    
    VirtualAllocEx = Kernel32.VirtualAllocEx
    VirtualAllocEx.restype = VOID
    res = VirtualAllocEx(hProcess, 
                         lpAddress, 
                         dwSize, 
                         flAllocationType, 
                         flProtect
    )

    if not res:
        raise WinError(GetLastError())
    return res


FILE_MAP_WRITE = SECTION_MAP_WRITE
FILE_MAP_READ = SECTION_MAP_READ
FILE_MAP_ALL_ACCESS = SECTION_ALL_ACCESS
FILE_MAP_COPY = 0x1
FILE_MAP_RESERVE = 0x80000000
FILE_MAP_TARGETS_INVALID = 0x40000000
FILE_MAP_LARGE_PAGES = 0x20000000


def VirtualQuery(lpAddress, lpBuffer, dwLength):
    VirtualQuery = Kernel32.VirtualQuery
    res = VirtualQuery(lpAddress, lpBuffer, dwLength)
    if not res:
        raise WinError(GetLastError())


def FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush):
    FlushViewOfFile = Kernel32.FlushViewOfFile
    res = FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush)
    if not res:
        raise WinError(GetLastError())
    

def UnmapViewOfFile(lpBaseAddress):
    UnmapViewOfFile = Kernel32.UnmapViewOfFile
    res = UnmapViewOfFile(lpBaseAddress)
    if not res:
        raise WinError(GetLastError())
    

def UnmapViewOfFile2(Process, BaseAddress, UnmapFlags):
    UnmapViewOfFile2 = Kernel32.UnmapViewOfFile2
    res = UnmapViewOfFile2(Process, BaseAddress, UnmapFlags)
    if not res:
        raise WinError(GetLastError())
    

def CreateFileMappingFromApp(hFile, SecurityAttributes, PageProtection, MaximumSize, Name):
    CreateFileMappingFromApp = Kernel32.CreateFileMappingFromApp
    res = CreateFileMappingFromApp(hFile, SecurityAttributes, PageProtection, MaximumSize, Name)
    if not res:
        raise WinError(GetLastError())
    return res


def MapViewOfFileFromApp(hFileMappingObject, DesiredAccess, FileOffset, NumberOfBytesToMap):
    MapViewOfFileFromApp = Kernel32.MapViewOfFileFromApp
    MapViewOfFileFromApp.restype = PVOID
    res = MapViewOfFileFromApp(hFileMappingObject, DesiredAccess, FileOffset, NumberOfBytesToMap)
    if not res:
        raise WinError(GetLastError())
    return res


def VirtualUnlockEx(Process, Address, Size):
    VirtualUnlockEx = Kernel32.VirtualUnlockEx
    res = VirtualUnlockEx(Process, Address, Size)
    if not res:
        raise WinError(GetLastError())
    

if _WIN32_WINNT >= _WIN32_WINNT_WIN10:
    def SetProcessValidCallTargets(hProcess, 
                                   VirtualAddress, 
                                   RegionSize, 
                                   NumberOfOffsets, 
                                   OffsetInformation):
        
        SetProcessValidCallTargets = Kernel32.SetProcessValidCallTargets
        res = SetProcessValidCallTargets(hProcess, 
                                         VirtualAddress, 
                                         RegionSize, 
                                         NumberOfOffsets, 
                                         OffsetInformation
        )

        if not res:
            raise WinError(GetLastError())
        

    def SetProcessValidCallTargetsForMappedView(Process, 
                                                VirtualAddress, 
                                                RegionSize, 
                                                NumberOfOffsets, 
                                                OffsetInformation, 
                                                Section, 
                                                ExpectedFileOffset):
        
        SetProcessValidCallTargetsForMappedView = Kernel32.SetProcessValidCallTargetsForMappedView
        res = SetProcessValidCallTargetsForMappedView(Process, 
                                                      VirtualAddress, 
                                                      RegionSize, 
                                                      NumberOfOffsets, 
                                                      OffsetInformation, 
                                                      Section, 
                                                      ExpectedFileOffset
        )

        if not res:
            raise WinError(GetLastError())
        

    def VirtualAllocFromApp(BaseAddress, Size, AllocationType, Protection):
        VirtualAllocFromApp = Kernel32.VirtualAllocFromApp
        VirtualAllocFromApp.restype = PVOID
        res = VirtualAllocFromApp(BaseAddress, Size, AllocationType, Protection)
        if not res:
            raise WinError(GetLastError())
        return res


    def VirtualProtectFromApp(lpAddress, dwSize, flNewProtect, lpflOldProtect):
        VirtualProtectFromApp = Kernel32.VirtualProtectFromApp
        res = VirtualProtectFromApp(lpAddress, dwSize, flNewProtect, lpflOldProtect)
        if not res:
            raise WinError(GetLastError())
        

    def OpenFileMappingFromApp(DesiredAccess, InheritHandle, Name):
        OpenFileMappingFromApp = Kernel32.OpenFileMappingFromApp
        res = OpenFileMappingFromApp(DesiredAccess, InheritHandle, Name)
        if not res:
            raise WinError(GetLastError())
        return res
    

if NTDDI_VERSION >= NTDDI_WIN10_RS4:
    def VirtualAlloc2FromApp(Process, 
                             BaseAddress, 
                             Size, 
                             AllocationType, 
                             PageProtection, 
                             ExtendedParameters, 
                             ParameterCount):
        
        VirtualAlloc2FromApp = Kernel32.VirtualAlloc2FromApp
        VirtualAlloc2FromApp.restype = PVOID
        res = VirtualAlloc2FromApp(Process, 
                                   BaseAddress, 
                                   Size, 
                                   AllocationType, 
                                   PageProtection, 
                                   ExtendedParameters, 
                                   ParameterCount
        )

        if not res:
            raise WinError(GetLastError())
        return res


    def MapViewOfFile3FromApp(FileMapping, 
                              Process, 
                              BaseAddress, 
                              Offset, 
                              ViewSize, 
                              AllocationType, 
                              PageProtection, 
                              ExtendedParameters, 
                              ParameterCount):
        
        MapViewOfFile3FromApp = Kernel32.MapViewOfFile3FromApp
        MapViewOfFile3FromApp.restype = PVOID
        res = MapViewOfFile3FromApp(FileMapping, 
                                    Process, 
                                    BaseAddress, 
                                    Offset, 
                                    ViewSize, 
                                    AllocationType, 
                                    PageProtection, 
                                    ExtendedParameters, 
                                    ParameterCount
        )

        if not res:
            raise WinError(GetLastError())
        return res


def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect):
    VirtualProtect = Kernel32.VirtualProtect
    res = VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
    if not res:
        raise WinError(GetLastError())


FILE_MAP_EXECUTE = SECTION_MAP_EXECUTE_EXPLICIT

FILE_CACHE_MAX_HARD_ENABLE = 0x00000001
FILE_CACHE_MAX_HARD_DISABLE = 0x00000002
FILE_CACHE_MIN_HARD_ENABLE = 0x00000004
FILE_CACHE_MIN_HARD_DISABLE = 0x00000008


def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect):
    VirtualProtectEx = Kernel32.VirtualProtectEx
    res = VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)
    if not res:
        raise WinError(GetLastError())
    

def VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength):
    VirtualQueryEx = Kernel32.VirtualQueryEx
    res = VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength)
    if not res:
        raise WinError(GetLastError())
    return res


def ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):
    ReadProcessMemory = Kernel32.ReadProcessMemory
    res = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
    if not res:
        raise WinError(GetLastError())


def WriteProcessMemory(hProcess: int, 
                       lpBaseAddress: int, 
                       lpBuffer: int, 
                       nSize: Any, 
                       lpNumberOfBytesWritten: int) -> None:
    
    WriteProcessMemory = Kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [HANDLE, 
                                   LPVOID, 
                                   LPCVOID, 
                                   SIZE_T, 
                                   SIZE_T
    ]

    res = WriteProcessMemory(hProcess, 
                             lpBaseAddress, 
                             lpBuffer, 
                             nSize, 
                             lpNumberOfBytesWritten
    )

    if not res:
        raise WinError(GetLastError())


def CreateFileMapping(hFile, 
                      lpFileMappingAttributes, 
                      flProtect, 
                      dwMaximumSizeHigh, 
                      dwMaximumSizeLow, 
                      lpName, 
                      unicode: bool = True):
    
    CreateFileMapping = Kernel32.CreateFileMappingW if unicode else Kernel32.CreateFileMappingA
    res = CreateFileMapping(hFile, 
                            lpFileMappingAttributes, 
                            flProtect, 
                            dwMaximumSizeHigh, 
                            dwMaximumSizeLow, 
                            lpName
    )

    if not res:
        raise WinError(GetLastError())
    return res


def OpenFileMapping(dwDesiredAccess, bInheritHandle, lpName, unicode: bool = True):
    OpenFileMapping = Kernel32.OpenFileMappingW if unicode else Kernel32.OpenFileMappingA
    res = OpenFileMapping(dwDesiredAccess, bInheritHandle, lpName)
    if not res:
        raise WinError(GetLastError())
    

def MapViewOfFile(hFileMappingObject, 
                  dwDesiredAccess, 
                  dwFileOffsetHigh, 
                  dwFileOffsetLow, 
                  dwNumberOfBytesToMap):
    
    MapViewOfFile = Kernel32.MapViewOfFile
    MapViewOfFile.restype = LPVOID
    res = MapViewOfFile(hFileMappingObject, 
                        dwDesiredAccess, 
                        dwFileOffsetHigh, 
                        dwFileOffsetLow, 
                        dwNumberOfBytesToMap
    )

    if not res:
        raise WinError(GetLastError())
    return res


def MapViewOfFileEx(hFileMappingObject, 
                    dwDesiredAccess, 
                    dwFileOffsetHigh, 
                    dwFileOffsetLow, 
                    dwNumberOfBytesToMap, 
                    lpBaseAddress):
    
    MapViewOfFileEx = Kernel32.MapViewOfFileEx
    MapViewOfFileEx.restype = LPVOID
    res = MapViewOfFileEx(hFileMappingObject, 
                          dwDesiredAccess, 
                          dwFileOffsetHigh, 
                          dwFileOffsetLow, 
                          dwNumberOfBytesToMap, 
                          lpBaseAddress
    )

    if not res:
        raise WinError(GetLastError())
    

def VirtualLock(lpAddress, dwSize):
    VirtualLock = Kernel32.VirtualLock
    res = VirtualLock(lpAddress, dwSize)
    if not res:
        raise WinError(GetLastError())
    

def VirtualUnlock(lpAddress, dwSize):
    VirtualUnlock = Kernel32.VirtualLock
    res = VirtualUnlock(lpAddress, dwSize)
    if not res:
        raise WinError(GetLastError())
    

def CreateMemoryResourceNotification(NotificationType):
    CreateMemoryResourceNotification = Kernel32.CreateMemoryResourceNotification
    res = CreateMemoryResourceNotification(NotificationType)
    if not res:
        raise WinError(GetLastError())
    return res


def QueryMemoryResourceNotification(ResourceNotificationHandle, ResourceState):
    QueryMemoryResourceNotification = Kernel32.QueryMemoryResourceNotification
    res = QueryMemoryResourceNotification(ResourceNotificationHandle, ResourceState)
    if not res:
        raise WinError(GetLastError())
    

def GetSystemFileCacheSize(lpMinimumFileCacheSize, lpMaximumFileCacheSize, lpFlags):
    GetSystemFileCacheSize = Kernel32.GetSystemFileCacheSize
    res = GetSystemFileCacheSize(lpMinimumFileCacheSize, lpMaximumFileCacheSize, lpFlags)
    if not res:
        raise WinError(GetLastError())
    

def SetSystemFileCacheSize(MinimumFileCacheSize, MaximumFileCacheSize, Flags):
    SetSystemFileCacheSize = Kernel32.SetSystemFileCacheSize
    res = SetSystemFileCacheSize(MinimumFileCacheSize, MaximumFileCacheSize, Flags)
    if not res:
        raise WinError(GetLastError())
    

def AllocateUserPhysicalPages(hProcess, NumberOfPages, PageArray):
    AllocateUserPhysicalPages = Kernel32.AllocateUserPhysicalPages
    res = AllocateUserPhysicalPages(hProcess, NumberOfPages, PageArray)
    if not res:
        raise WinError(GetLastError())
    

def FreeUserPhysicalPages(hProcess, NumberOfPages, PageArray):
    FreeUserPhysicalPages = Kernel32.FreeUserPhysicalPages
    res = FreeUserPhysicalPages(hProcess, NumberOfPages, PageArray)
    if not res:
        raise WinError(GetLastError())
    

def MapUserPhysicalPages(VirtualAddress, NumberOfPages, PageArray):
    MapUserPhysicalPages = Kernel32.MapUserPhysicalPages
    res = MapUserPhysicalPages(VirtualAddress, NumberOfPages, PageArray)
    if not res:
        raise WinError(GetLastError())
    

def AllocateUserPhysicalPagesNuma(hProcess, NumberOfPages, PageArray, nndPreferred):
    AllocateUserPhysicalPagesNuma = Kernel32.AllocateUserPhysicalPagesNuma
    res = AllocateUserPhysicalPagesNuma(hProcess, NumberOfPages, PageArray, nndPreferred)
    if not res:
        raise WinError(GetLastError())
    

def CreateFileMappingNuma(hFile, 
                          lpFileMappingAttributes, 
                          flProtect, 
                          dwMaximumSizeHigh, 
                          dwMaximumSizeLow, 
                          lpName, 
                          nndPreferred, 
                          unicode: bool = True):
    
    CreateFileMappingNuma = Kernel32.CreateFileMappingNumaW if unicode else Kernel32.CreateFileMappingNumaA
    res = CreateFileMappingNuma(hFile, 
                                lpFileMappingAttributes, 
                                flProtect, 
                                dwMaximumSizeHigh, 
                                dwMaximumSizeLow, 
                                lpName, 
                                nndPreferred
    )

    if not res:
        raise WinError(GetLastError())
    return res


def VirtualAllocExNuma(hProcess, lpAddress, dwSize, flAllocationType, flProtect, nndPreferred):
    VirtualAllocExNuma = Kernel32.VirtualAllocExNuma
    VirtualAllocExNuma.restype = LPVOID
    res = VirtualAllocExNuma(hProcess, lpAddress, dwSize, flAllocationType, flProtect, nndPreferred)
    if not res:
        raise WinError(GetLastError())
    

if _WIN32_WINNT >= _WIN32_WINNT_WIN8:
    MEHC_PATROL_SCRUBBER_PRESENT = 0x1


    def GetMemoryErrorHandlingCapabilities(Capabilities):
        GetMemoryErrorHandlingCapabilities = Kernel32.GetMemoryErrorHandlingCapabilities
        res = GetMemoryErrorHandlingCapabilities(Capabilities)
        if not res:
            raise WinError(GetLastError())
        

    def PrefetchVirtualMemory(hProcess, NumberOfEntries, VirtualAddresses, Flags):
        PrefetchVirtualMemory = Kernel32.PrefetchVirtualMemory
        res = PrefetchVirtualMemory(hProcess, NumberOfEntries, VirtualAddresses, Flags)
        if not res:
            raise WinError(GetLastError())
        

    BAD_MEMORY_CALLBACK_ROUTINE = WINAPI(VOID, VOID)
    PBAD_MEMORY_CALLBACK_ROUTINE = POINTER(BAD_MEMORY_CALLBACK_ROUTINE)

    def RegisterBadMemoryNotification(Callback):
        RegisterBadMemoryNotification = Kernel32.RegisterBadMemoryNotification
        RegisterBadMemoryNotification.restype = PVOID
        res = RegisterBadMemoryNotification(Callback)
        if not res:
            raise WinError(GetLastError())
        return res


    def UnregisterBadMemoryNotification(RegistrationHandle):
        UnregisterBadMemoryNotification = Kernel32.UnregisterBadMemoryNotification
        res = UnregisterBadMemoryNotification(RegistrationHandle)
        if not res:
            raise WinError(GetLastError())
    

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


    def QueryVirtualMemoryInformation(Process, 
                                      VirtualAddress, 
                                      MemoryInformationClass, 
                                      MemoryInformation, 
                                      MemoryInformationSize, 
                                      ReturnSize):
        
        QueryVirtualMemoryInformation = Kernel32.QueryVirtualMemoryInformation
        res = QueryVirtualMemoryInformation(Process, 
                                            VirtualAddress, 
                                            MemoryInformationClass, 
                                            MemoryInformation, 
                                            MemoryInformationSize, 
                                            ReturnSize
        )

        if not res:
            raise WinError(GetLastError())
    

if NTDDI_VERSION >= NTDDI_WIN10_RS2:
    def MapViewOfFileNuma2(FileMappingHandle, 
                           ProcessHandle, 
                           Offset, 
                           BaseAddress, 
                           ViewSize, 
                           AllocationType, 
                           PageProtection, 
                           PreferredNode):
        
        MapViewOfFileNuma2 = Kernel32.MapViewOfFileNuma2
        MapViewOfFileNuma2.restype = PVOID
        res = MapViewOfFileNuma2(FileMappingHandle, 
                                 ProcessHandle, 
                                 Offset, 
                                 BaseAddress, 
                                 ViewSize, 
                                 AllocationType, 
                                 PageProtection, 
                                 PreferredNode
        )

        if not res:
            raise WinError(GetLastError())


    def MapViewOfFile2(FileMappingHandle, 
                       ProcessHandle, 
                       Offset, 
                       BaseAddress, 
                       ViewSize, 
                       AllocationType, 
                       PageProtection):
        
        MapViewOfFile2 = Kernel32.MapViewOfFile2
        MapViewOfFile2.restype = PVOID
        res = MapViewOfFile2(FileMappingHandle, 
                             ProcessHandle, 
                             Offset, 
                             BaseAddress, 
                             ViewSize, 
                             AllocationType, 
                             PageProtection
        )

        if not res:
            raise WinError(GetLastError())
        

if NTDDI_VERSION >= NTDDI_WIN10_RS4:
    def VirtualAlloc2(Process, 
                      BaseAddress, 
                      Size, 
                      AllocationType, 
                      PageProtection, 
                      ExtendedParameters, 
                      ParameterCount):
        
        VirtualAlloc2 = Kernel32.VirtualAlloc2
        VirtualAlloc2.restype = PVOID
        res = VirtualAlloc2(Process, 
                            BaseAddress, 
                            Size, 
                            AllocationType, 
                            PageProtection, 
                            ExtendedParameters, 
                            ParameterCount
        )

        if not res:
            raise WinError(GetLastError())
        return res


    def MapViewOfFile3(FileMapping, 
                       Process, 
                       BaseAddress, 
                       Offset, 
                       ViewSize, 
                       AllocationType, 
                       PageProtection, 
                       ExtendedParameters, 
                       ParameterCount):
        
        MapViewOfFile3 = Kernel32.MapViewOfFile3
        MapViewOfFile3.restype = PVOID
        res = MapViewOfFile3(FileMapping, 
                             Process, 
                             BaseAddress, 
                             Offset, 
                             ViewSize, 
                             AllocationType, 
                             PageProtection, 
                             ExtendedParameters, 
                             ParameterCount
        )

        if not res:
            raise WinError(GetLastError())
        return res


if NTDDI_VERSION >= NTDDI_WIN10_RS5:
    def CreateFileMapping2(File, 
                           SecurityAttributes, 
                           DesiredAccess, 
                           PageProtection, 
                           AllocationAttributes, 
                           MaximumSize, 
                           Name, 
                           ExtendedParameters, 
                           ParameterCount):
        
        CreateFileMapping2 = Kernel32.CreateFileMapping2
        CreateFileMapping2.restype = HANDLE
        res = CreateFileMapping2(File, 
                                 SecurityAttributes, 
                                 DesiredAccess, 
                                 PageProtection, 
                                 AllocationAttributes, 
                                 MaximumSize, 
                                 Name, 
                                 ExtendedParameters, 
                                 ParameterCount
        )
        
        if not res:
            raise WinError(GetLastError())
        return res


def GetLargePageMinimum():
    GetLargePageMinimum = Kernel32.GetLargePageMinimum
    return GetLargePageMinimum()


def GetProcessWorkingSetSizeEx(hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags):
    GetProcessWorkingSetSizeEx = Kernel32.GetProcessWorkingSetSizeEx
    res = GetProcessWorkingSetSizeEx(hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags)
    if not res:
        raise WinError(GetLastError())
    

def SetProcessWorkingSetSizeEx(hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags):
    SetProcessWorkingSetSizeEx = Kernel32.SetProcessWorkingSetSizeEx
    res = SetProcessWorkingSetSizeEx(hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags)
    if not res:
        raise WinError(GetLastError())
    

def GetWriteWatch(dwFlags, lpBaseAddress, dwRegionSize, lpAddresses, lpdwCount, lpdwGranularity):
    GetWriteWatch = Kernel32.GetWriteWatch
    GetWriteWatch.restype = UINT
    res = GetWriteWatch(dwFlags, lpBaseAddress, dwRegionSize, lpAddresses, lpdwCount, lpdwGranularity)
    if not res:
        raise WinError()
    return res


def ResetWriteWatch(lpBaseAddress, dwRegionSize):
    ResetWriteWatch = Kernel32.ResetWriteWatch
    ResetWriteWatch.restype = UINT
    res = ResetWriteWatch(lpBaseAddress, dwRegionSize)
    if not res:
        raise WinError(GetLastError())
    return res


def VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType):
    VirtualFreeEx = Kernel32.VirtualFreeEx
    res = VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType)
    if not res:
        raise WinError(GetLastError())
    

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

def DiscardVirtualMemory(VirtualAddress, Size):
    DiscardVirtualMemory = Kernel32.DiscardVirtualMemory
    DiscardVirtualMemory.restype = DWORD
    res = DiscardVirtualMemory(VirtualAddress, Size)
    if res:
        raise WinError(res)


def OfferVirtualMemory(VirtualAddress, Size, Priority):
    OfferVirtualMemory = Kernel32.OfferVirtualMemory
    OfferVirtualMemory.restype = DWORD
    res = OfferVirtualMemory(VirtualAddress, Size, Priority)
    if res:
        raise WinError(res)
    

def ReclaimVirtualMemory(VirtualAddress, Size):
    ReclaimVirtualMemory = Kernel32.ReclaimVirtualMemory
    res = ReclaimVirtualMemory(VirtualAddress, Size)
    if res:
        raise WinError(res)
    

if _WIN32_WINNT >= _WIN32_WINNT_WIN8:
    def UnmapViewOfFileEx(BaseAddress, UnmapFlags):
        UnmapViewOfFileEx = Kernel32.UnmapViewOfFileEx
        res = UnmapViewOfFileEx(BaseAddress, UnmapFlags)
        if not res:
            raise WinError(GetLastError())
        

