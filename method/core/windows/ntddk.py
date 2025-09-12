# codiing = 'utf-8'

import sys
import enum
import platform
from ctypes import *

try:
    from error import *
    from win_NT import *
    from ntstatus import *
    from public_dll import *
except ImportError:
    from .error import *
    from .win_NT import *
    from .ntstatus import *
    from .public_dll import *

# ntddk.h

UUID = GUID

class _LOADER_PARAMETER_BLOCK(Structure):
    pass

class _CREATE_DISK(Structure):
    pass

class _DRIVE_LAYOUT_INFORMATION_EX(Structure):
    pass

class _SET_PARTITION_INFORMATION_EX(Structure):
    pass

class _DISK_GEOMETRY_EX(Structure):
    pass

class _BUS_HANDLER(Structure):
    pass

PBUS_HANDLER = POINTER(_BUS_HANDLER)

class _DEVICE_HANDLER_OBJECT(Structure):
    pass

PDEVICE_HANDLER_OBJECT = POINTER(_DEVICE_HANDLER_OBJECT)

class _PEB(Structure):
    pass

PPEB = POINTER(_PEB)

class _IMAGE_NT_HEADERS(Structure):
    pass

PIMAGE_NT_HEADERS32 = POINTER(_IMAGE_NT_HEADERS)

class _IMAGE_NT_HEADERS64(Structure):
    pass

PIMAGE_NT_HEADERS64 = POINTER(_IMAGE_NT_HEADERS64)

PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS64 if sys.maxsize > 2 ** 32 else PIMAGE_NT_HEADERS32

class _ZONE_SEGMENT_HEADER(Structure):
    _fields_ = [('SegmentList', SINGLE_LIST_ENTRY),
                ('Reserved', PVOID)
    ]

ZONE_SEGMENT_HEADER = _ZONE_SEGMENT_HEADER
PZONE_SEGMENT_HEADER = POINTER(ZONE_SEGMENT_HEADER)

class _ZONE_HEADER(Structure):
    _fields_ = [('FreeList', SINGLE_LIST_ENTRY),
                ('SegmentList', SINGLE_LIST_ENTRY),
                ('BlockSize', ULONG),
                ('TotalSegmentSize', ULONG),
    ]

ZONE_HEADER = _ZONE_HEADER
PZONE_HEADER = POINTER(ZONE_HEADER)

PROTECTED_POOL                    = 0x80000000

DO_DEVICE_HAS_NAME =                0x00000040
DO_SYSTEM_BOOT_PARTITION =          0x00000100
DO_LONG_TERM_REQUESTS =             0x00000200
DO_NEVER_LAST_DEVICE =              0x00000400
DO_LOW_PRIORITY_FILESYSTEM =        0x00010000
DO_SUPPORTS_TRANSACTIONS =          0x00040000
DO_FORCE_NEITHER_IO =               0x00080000
DO_VOLUME_DEVICE_OBJECT =           0x00100000
DO_SYSTEM_SYSTEM_PARTITION =        0x00200000
DO_SYSTEM_CRITICAL_PARTITION =      0x00400000
DO_DISALLOW_EXECUTE =               0x00800000

ArcSystem = 0
CentralProcessor = 1
FloatingPointProcessor = 2
PrimaryIcache = 3
PrimaryDcache = 4
SecondaryIcache = 5
SecondaryDcache = 6
SecondaryCache = 7
EisaAdapter = 8
TcAdapter = 9
ScsiAdapter = 10
DtiAdapter = 11
MultiFunctionAdapter = 12
DiskController = 13
TapeController = 14
CdromController = 15
WormController = 16
SerialController = 17
NetworkController = 18
DisplayController = 19
ParallelController = 20
PointerController = 21
KeyboardController = 22
AudioController = 23
OtherController = 24
DiskPeripheral = 25
FloppyDiskPeripheral = 26
TapePeripheral = 27
ModemPeripheral = 28
MonitorPeripheral = 29
PrinterPeripheral = 30
PointerPeripheral = 31
KeyboardPeripheral = 32
TerminalPeripheral = 33
OtherPeripheral = 34
LinePeripheral = 35
NetworkPeripheral = 36
SystemMemory = 37
DockingInformation = 38
RealModeIrqRoutingTable = 39
RealModePCIEnumeration = 40
MaximumType = 41

class _CONFIGURATION_TYPE(enum.IntFlag):
    ArcSystem = 0
    CentralProcessor = 1
    FloatingPointProcessor = 2
    PrimaryIcache = 3
    PrimaryDcache = 4
    SecondaryIcache = 5
    SecondaryDcache = 6
    SecondaryCache = 7
    EisaAdapter = 8
    TcAdapter = 9
    ScsiAdapter = 10
    DtiAdapter = 11
    MultiFunctionAdapter = 12
    DiskController = 13
    TapeController = 14
    CdromController = 15
    WormController = 16
    SerialController = 17
    NetworkController = 18
    DisplayController = 19
    ParallelController = 20
    PointerController = 21
    KeyboardController = 22
    AudioController = 23
    OtherController = 24
    DiskPeripheral = 25
    FloppyDiskPeripheral = 26
    TapePeripheral = 27
    ModemPeripheral = 28
    MonitorPeripheral = 29
    PrinterPeripheral = 30
    PointerPeripheral = 31
    KeyboardPeripheral = 32
    TerminalPeripheral = 33
    OtherPeripheral = 34
    LinePeripheral = 35
    NetworkPeripheral = 36
    SystemMemory = 37
    DockingInformation = 38
    RealModeIrqRoutingTable = 39
    RealModePCIEnumeration = 40
    MaximumType = 41

CONFIGURATION_TYPE = _CONFIGURATION_TYPE
PCONFIGURATION_TYPE = CONFIGURATION_TYPE

IRP_MN_QUERY_DIRECTORY =            0x01
IRP_MN_NOTIFY_CHANGE_DIRECTORY =    0x02

IRP_MN_USER_FS_REQUEST =            0x00
IRP_MN_MOUNT_VOLUME =               0x01
IRP_MN_VERIFY_VOLUME =              0x02
IRP_MN_LOAD_FILE_SYSTEM =           0x03
IRP_MN_TRACK_LINK =                 0x04
IRP_MN_KERNEL_CALL =                0x04

IRP_MN_LOCK =                       0x01
IRP_MN_UNLOCK_SINGLE =              0x02
IRP_MN_UNLOCK_ALL =                 0x03
IRP_MN_UNLOCK_ALL_BY_KEY =          0x04

IRP_MN_FLUSH_AND_PURGE =          0x01

IRP_MN_NORMAL =                     0x00
IRP_MN_DPC =                        0x01
IRP_MN_MDL =                        0x02
IRP_MN_COMPLETE =                   0x04
IRP_MN_COMPRESSED =                 0x08

IRP_MN_MDL_DPC =                    (IRP_MN_MDL | IRP_MN_DPC)
IRP_MN_COMPLETE_MDL =               (IRP_MN_COMPLETE | IRP_MN_MDL)
IRP_MN_COMPLETE_MDL_DPC =           (IRP_MN_COMPLETE_MDL | IRP_MN_DPC)

IRP_MN_QUERY_LEGACY_BUS_INFORMATION = 0x18

IO_CHECK_CREATE_PARAMETERS =      0x0200
IO_ATTACH_DEVICE =                0x0400
IO_IGNORE_SHARE_ACCESS_CHECK =    0x0800

class _KEY_VALUE_FULL_INFORMATION(Structure):   # from ntos.h
    _fields_ = [('TitleIndex', ULONG),
                ('Type', ULONG),
                ('DataOffset', ULONG),
                ('DataLength', ULONG),
                ('NameLength', ULONG),
                ('Name', WCHAR * 1),
    ]  

KEY_VALUE_FULL_INFORMATION = _KEY_VALUE_FULL_INFORMATION
PKEY_VALUE_FULL_INFORMATION = POINTER(KEY_VALUE_FULL_INFORMATION)

InterfaceTypeUndefined = -1
Internal = 0
Isa = 1
Eisa = 2
MicroChannel = 3
TurboChannel = 4
PCIBus = 5
VMEBus = 6
NuBus = 7
PCMCIABus = 8
CBus = 9
MPIBus = 10
MPSABus = 11
ProcessorInternal = 12
InternalPowerBus = 13
PNPISABus = 14
PNPBus = 15
Vmcs = 16
ACPIBus = 17
MaximumInterfaceType = 18

class _INTERFACE_TYPE(enum.IntFlag):    # from ntos.h
    InterfaceTypeUndefined = -1
    Internal = 0
    Isa = 1
    Eisa = 2
    MicroChannel = 3
    TurboChannel = 4
    PCIBus = 5
    VMEBus = 6
    NuBus = 7
    PCMCIABus = 8
    CBus = 9
    MPIBus = 10
    MPSABus = 11
    ProcessorInternal = 12
    InternalPowerBus = 13
    PNPISABus = 14
    PNPBus = 15
    Vmcs = 16
    ACPIBus = 17
    MaximumInterfaceType = 18

INTERFACE_TYPE = _INTERFACE_TYPE
PINTERFACE_TYPE = INTERFACE_TYPE

IoQueryDeviceIdentifier = 0
IoQueryDeviceConfigurationData = 1
IoQueryDeviceComponentInformation = 2
IoQueryDeviceMaxData = 3

class _IO_QUERY_DEVICE_DATA_FORMAT(enum.IntFlag):
    IoQueryDeviceIdentifier = 0
    IoQueryDeviceConfigurationData = 1
    IoQueryDeviceComponentInformation = 2
    IoQueryDeviceMaxData = 3

IO_QUERY_DEVICE_DATA_FORMAT = _IO_QUERY_DEVICE_DATA_FORMAT
PIO_QUERY_DEVICE_DATA_FORMAT = IO_QUERY_DEVICE_DATA_FORMAT

CSHORT = SHORT
PCSHORT = CSHORT

KSPIN_LOCK = ULONG_PTR
PKSPIN_LOCK = POINTER(KSPIN_LOCK)

class _KDEVICE_QUEUE(Structure):    # from ntos.h
    _fields_ = [('Type', CSHORT),
                ('Size', CSHORT),
                ('DeviceListHead', LIST_ENTRY),
                ('Lock', KSPIN_LOCK),
    ]

    if platform.platform().lower() == 'amd64':
        class Busy(Union):
            class ReHi(LittleEndianStructure):
                _fields_ = [('Reserved', LONG64, 8),
                            ('Hint', LONG64, 56)
                ]

            _fields_ = [('Busy', BOOLEAN),
                        ('ReHi', ReHi)
            ]

        _fields_.append(('Busy', Busy))
    else:
        _fields_.append(('Busy', BOOLEAN))

KDEVICE_QUEUE = _KDEVICE_QUEUE


class _CONTROLLER_OBJECT(Structure):
    _fields_ = [('Type', CSHORT),
                ('Size', CSHORT),
                ('ControllerExtension', PVOID),
                ('DeviceWaitQueue', KDEVICE_QUEUE),
                ('Spare1', ULONG),
                ('Spare2', LARGE_INTEGER),
    ]

CONTROLLER_OBJECT = _CONTROLLER_OBJECT
PCONTROLLER_OBJECT = POINTER(CONTROLLER_OBJECT)

DRVO_REINIT_REGISTERED =          0x00000008
DRVO_INITIALIZED =                0x00000010
DRVO_BOOTREINIT_REGISTERED =      0x00000020
DRVO_LEGACY_RESOURCES =           0x00000040


def NtOpenProcess(ProcessHandle = HANDLE(),
                  DesiredAccess: int = ACCESS_MASK(), 
                  ObjectAttributes = OBJECT_ATTRIBUTES(), 
                  ClientId = CLIENT_ID()) -> int:

    NtOpenProcess = ntdll.NtOpenProcess
    NtOpenProcess.argtypes = [PHANDLE, 
                              ACCESS_MASK, 
                              POBJECT_ATTRIBUTES, 
                              PCLIENT_ID
    ]

    NtOpenProcess.restype = VOID
    res = NtOpenProcess(byref(ProcessHandle), 
                        DesiredAccess, 
                        byref(ObjectAttributes), 
                        byref(ClientId)
    )

    if not NT_SUCCESS(res):
        raise WinError(RtlNtStatusToDosError(res))
    return ProcessHandle


def ZwOpenProcess(ProcessHandle = HANDLE(),
                  DesiredAccess: int = ACCESS_MASK(), 
                  ObjectAttributes = OBJECT_ATTRIBUTES(), 
                  ClientId = CLIENT_ID()) -> int:

    ZwOpenProcess = ntdll.ZwOpenProcess
    ZwOpenProcess.argtypes = [PHANDLE, 
                              ACCESS_MASK, 
                              POBJECT_ATTRIBUTES, 
                              PCLIENT_ID
    ]

    ZwOpenProcess.restype = VOID
    res = ZwOpenProcess(byref(ProcessHandle), 
                        DesiredAccess, 
                        byref(ObjectAttributes), 
                        byref(ClientId)
    )

    if not NT_SUCCESS(res):
        raise WinError(RtlNtStatusToDosError(res))
    return ProcessHandle


def NtTerminateProcess(ProcessHandle: int, ExitStatus: int) -> None:
    NtTerminateProcess = ntdll.NtTerminateProcess
    NtTerminateProcess.argtypes = [HANDLE, VOID]
    NtTerminateProcess.restype = VOID
    res = NtTerminateProcess(ProcessHandle, ExitStatus)
    
    if not NT_SUCCESS(res):
        raise WinError(RtlNtStatusToDosError(res))
    

def ZwTerminateProcess(hProcess: int, uExitCode: int) -> None:
    ZwTerminateProcess = ntdll.ZwTerminateProcess
    ZwTerminateProcess.argtypes = [HANDLE, VOID]
    ZwTerminateProcess.restype = VOID
    res = ZwTerminateProcess(hProcess, uExitCode)

    if not NT_SUCCESS(res):
        raise WinError(RtlNtStatusToDosError(res))
