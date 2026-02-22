# coding = 'utf-8'
# winsvc.h

import enum
from method.System.winnt import *
from method.System.sdkddkver import *
from method.System.winusutypes import *
from method.System.public_dll import advapi32
from method.System.errcheck import win32_to_errcheck

SERVICES_ACTIVE_DATABASEW = "ServicesActive"
SERVICES_FAILED_DATABASEW = "ServicesFailed"

SERVICES_ACTIVE_DATABASEA = b"ServicesActive"
SERVICES_FAILED_DATABASEA = b"ServicesFailed"

SC_GROUP_IDENTIFIERW = '+'
SC_GROUP_IDENTIFIERA = b'+'

SERVICES_ACTIVE_DATABASE = SERVICES_ACTIVE_DATABASEW if UNICODE else SERVICES_ACTIVE_DATABASEA
SERVICES_FAILED_DATABASE = SERVICES_FAILED_DATABASEW if UNICODE else SERVICES_FAILED_DATABASEA

SC_GROUP_IDENTIFIER = SC_GROUP_IDENTIFIERW if UNICODE else SC_GROUP_IDENTIFIERA

SERVICE_NO_CHANGE = 0xffffffff

SERVICE_ACTIVE = 0x00000001
SERVICE_INACTIVE = 0x00000002
SERVICE_STATE_ALL = (SERVICE_ACTIVE | SERVICE_INACTIVE)

SERVICE_CONTROL_STOP = 0x00000001
SERVICE_CONTROL_PAUSE = 0x00000002
SERVICE_CONTROL_CONTINUE = 0x00000003
SERVICE_CONTROL_INTERROGATE = 0x00000004
SERVICE_CONTROL_SHUTDOWN = 0x00000005
SERVICE_CONTROL_PARAMCHANGE = 0x00000006
SERVICE_CONTROL_NETBINDADD = 0x00000007
SERVICE_CONTROL_NETBINDREMOVE = 0x00000008
SERVICE_CONTROL_NETBINDENABLE = 0x00000009
SERVICE_CONTROL_NETBINDDISABLE = 0x0000000A
SERVICE_CONTROL_DEVICEEVENT = 0x0000000B
SERVICE_CONTROL_HARDWAREPROFILECHANGE = 0x0000000C
SERVICE_CONTROL_POWEREVENT = 0x0000000D
SERVICE_CONTROL_SESSIONCHANGE = 0x0000000E
SERVICE_CONTROL_PRESHUTDOWN = 0x0000000F
SERVICE_CONTROL_TIMECHANGE = 0x00000010
SERVICE_CONTROL_USER_LOGOFF = 0x00000011
SERVICE_CONTROL_TRIGGEREVENT = 0x00000020
SERVICE_CONTROL_LOWRESOURCES = 0x00000060
SERVICE_CONTROL_SYSTEMLOWRESOURCES = 0x00000061

SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004
SERVICE_CONTINUE_PENDING = 0x00000005
SERVICE_PAUSE_PENDING = 0x00000006
SERVICE_PAUSED = 0x00000007

SERVICE_ACCEPT_STOP = 0x00000001
SERVICE_ACCEPT_PAUSE_CONTINUE = 0x00000002
SERVICE_ACCEPT_SHUTDOWN = 0x00000004
SERVICE_ACCEPT_PARAMCHANGE = 0x00000008
SERVICE_ACCEPT_NETBINDCHANGE = 0x00000010
SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020
SERVICE_ACCEPT_POWEREVENT = 0x00000040
SERVICE_ACCEPT_SESSIONCHANGE = 0x00000080
SERVICE_ACCEPT_PRESHUTDOWN = 0x00000100
SERVICE_ACCEPT_TIMECHANGE = 0x00000200
SERVICE_ACCEPT_TRIGGEREVENT = 0x00000400
SERVICE_ACCEPT_USER_LOGOFF = 0x00000800
SERVICE_ACCEPT_LOWRESOURCES = 0x00002000
SERVICE_ACCEPT_SYSTEMLOWRESOURCES = 0x00004000

SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_CREATE_SERVICE = 0x0002
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SC_MANAGER_LOCK = 0x0008
SC_MANAGER_QUERY_LOCK_STATUS = 0x0010
SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020

SC_MANAGER_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                         SC_MANAGER_CONNECT | 
                         SC_MANAGER_CREATE_SERVICE | 
                         SC_MANAGER_ENUMERATE_SERVICE | 
                         SC_MANAGER_LOCK | 
                         SC_MANAGER_QUERY_LOCK_STATUS | 
                         SC_MANAGER_MODIFY_BOOT_CONFIG
)

SERVICE_QUERY_CONFIG = 0x0001
SERVICE_CHANGE_CONFIG = 0x0002
SERVICE_QUERY_STATUS = 0x0004
SERVICE_ENUMERATE_DEPENDENTS = 0x0008
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_PAUSE_CONTINUE = 0x0040
SERVICE_INTERROGATE = 0x0080

SERVICE_USER_DEFINED_CONTROL = 0x0100

SERVICE_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                      SERVICE_QUERY_CONFIG | 
                      SERVICE_CHANGE_CONFIG | 
                      SERVICE_QUERY_STATUS | 
                      SERVICE_ENUMERATE_DEPENDENTS | 
                      SERVICE_START | 
                      SERVICE_STOP | 
                      SERVICE_PAUSE_CONTINUE | 
                      SERVICE_INTERROGATE | 
                      
                      SERVICE_USER_DEFINED_CONTROL
)

SERVICE_RUNS_IN_SYSTEM_PROCESS = 0x00000001

SERVICE_CONFIG_DESCRIPTION = 1
SERVICE_CONFIG_FAILURE_ACTIONS = 2
SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3
SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4
SERVICE_CONFIG_SERVICE_SID_INFO = 5
SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 6
SERVICE_CONFIG_PRESHUTDOWN_INFO = 7
SERVICE_CONFIG_TRIGGER_INFO = 8
SERVICE_CONFIG_PREFERRED_NODE = 9
SERVICE_CONFIG_LAUNCH_PROTECTED = 12

SERVICE_NOTIFY_STATUS_CHANGE_1 = 1
SERVICE_NOTIFY_STATUS_CHANGE_2 = 2

SERVICE_NOTIFY_STATUS_CHANGE = SERVICE_NOTIFY_STATUS_CHANGE_2

SERVICE_NOTIFY_STOPPED = 0x00000001
SERVICE_NOTIFY_START_PENDING = 0x00000002
SERVICE_NOTIFY_STOP_PENDING = 0x00000004
SERVICE_NOTIFY_RUNNING = 0x00000008
SERVICE_NOTIFY_CONTINUE_PENDING = 0x00000010
SERVICE_NOTIFY_PAUSE_PENDING = 0x00000020
SERVICE_NOTIFY_PAUSED = 0x00000040
SERVICE_NOTIFY_CREATED = 0x00000080
SERVICE_NOTIFY_DELETED = 0x00000100
SERVICE_NOTIFY_DELETE_PENDING = 0x00000200

SERVICE_STOP_REASON_FLAG_MIN = 0x00000000
SERVICE_STOP_REASON_FLAG_UNPLANNED = 0x10000000
SERVICE_STOP_REASON_FLAG_CUSTOM = 0x20000000
SERVICE_STOP_REASON_FLAG_PLANNED = 0x40000000
SERVICE_STOP_REASON_FLAG_MAX = 0x80000000

SERVICE_STOP_REASON_MAJOR_MIN = 0x00000000
SERVICE_STOP_REASON_MAJOR_OTHER = 0x00010000
SERVICE_STOP_REASON_MAJOR_HARDWARE = 0x00020000
SERVICE_STOP_REASON_MAJOR_OPERATINGSYSTEM = 0x00030000
SERVICE_STOP_REASON_MAJOR_SOFTWARE = 0x00040000
SERVICE_STOP_REASON_MAJOR_APPLICATION = 0x00050000
SERVICE_STOP_REASON_MAJOR_NONE = 0x00060000
SERVICE_STOP_REASON_MAJOR_MAX = 0x00070000
SERVICE_STOP_REASON_MAJOR_MIN_CUSTOM = 0x00400000
SERVICE_STOP_REASON_MAJOR_MAX_CUSTOM = 0x00ff0000

SERVICE_STOP_REASON_MINOR_MIN = 0x00000000
SERVICE_STOP_REASON_MINOR_OTHER = 0x00000001
SERVICE_STOP_REASON_MINOR_MAINTENANCE = 0x00000002
SERVICE_STOP_REASON_MINOR_INSTALLATION = 0x00000003
SERVICE_STOP_REASON_MINOR_UPGRADE = 0x00000004
SERVICE_STOP_REASON_MINOR_RECONFIG = 0x00000005
SERVICE_STOP_REASON_MINOR_HUNG = 0x00000006
SERVICE_STOP_REASON_MINOR_UNSTABLE = 0x00000007
SERVICE_STOP_REASON_MINOR_DISK = 0x00000008
SERVICE_STOP_REASON_MINOR_NETWORKCARD = 0x00000009
SERVICE_STOP_REASON_MINOR_ENVIRONMENT = 0x0000000a
SERVICE_STOP_REASON_MINOR_HARDWARE_DRIVER = 0x0000000b
SERVICE_STOP_REASON_MINOR_OTHERDRIVER = 0x0000000c
SERVICE_STOP_REASON_MINOR_SERVICEPACK = 0x0000000d
SERVICE_STOP_REASON_MINOR_SOFTWARE_UPDATE = 0x0000000e
SERVICE_STOP_REASON_MINOR_SECURITYFIX = 0x0000000f
SERVICE_STOP_REASON_MINOR_SECURITY = 0x00000010
SERVICE_STOP_REASON_MINOR_NETWORK_CONNECTIVITY = 0x00000011
SERVICE_STOP_REASON_MINOR_WMI = 0x00000012
SERVICE_STOP_REASON_MINOR_SERVICEPACK_UNINSTALL = 0x00000013
SERVICE_STOP_REASON_MINOR_SOFTWARE_UPDATE_UNINSTALL = 0x00000014
SERVICE_STOP_REASON_MINOR_SECURITYFIX_UNINSTALL = 0x00000015
SERVICE_STOP_REASON_MINOR_MMC = 0x00000016
SERVICE_STOP_REASON_MINOR_NONE = 0x00000017
SERVICE_STOP_REASON_MINOR_MEMOTYLIMIT = 0x00000018
SERVICE_STOP_REASON_MINOR_MAX = 0x00000019
SERVICE_STOP_REASON_MINOR_MIN_CUSTOM = 0x00000100
SERVICE_STOP_REASON_MINOR_MAX_CUSTOM = 0x0000FFFF

SERVICE_CONTROL_STATUS_REASON_INFO = 1

SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL = 1
SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY = 2
SERVICE_TRIGGER_TYPE_DOMAIN_JOIN = 3
SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT = 4
SERVICE_TRIGGER_TYPE_GROUP_POLICY = 5
SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT = 6
SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE = 7
SERVICE_TRIGGER_TYPE_CUSTOM = 20
SERVICE_TRIGGER_TYPE_AGGREGATE = 30

SERVICE_TRIGGER_DATA_TYPE_BINARY = 1
SERVICE_TRIGGER_DATA_TYPE_STRING = 2
SERVICE_TRIGGER_DATA_TYPE_LEVEL = 3
SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY = 4
SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL = 5

SERVICE_START_REASON_DEMAND = 0x00000001
SERVICE_START_REASON_AUTO = 0x00000002
SERVICE_START_REASON_TRIGGER = 0x00000004
SERVICE_START_REASON_RESTART_ON_FAILURE = 0x00000008
SERVICE_START_REASON_DELAYEDAUTO = 0x00000010

SERVICE_DYNAMIC_INFORMATION_LEVEL_START_REASON = 1

SERVICE_LAUNCH_PROTECTED_NONE = 0
SERVICE_LAUNCH_PROTECTED_WINDOWS = 1
SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT = 2
SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT = 3

class _SERVICE_DESCRIPTIONA(Structure):
    _fields_ = [('lpDescription', LPSTR)]

SERVICE_DESCRIPTIONA = _SERVICE_DESCRIPTIONA
LPSERVICE_DESCRIPTIONA = POINTER(SERVICE_DESCRIPTIONA)

class _SERVICE_DESCRIPTIONW(Structure):
    _fields_ = [('lpDescription', LPWSTR)]

SERVICE_DESCRIPTIONW = _SERVICE_DESCRIPTIONW
LPSERVICE_DESCRIPTIONW = POINTER(SERVICE_DESCRIPTIONW)

SERVICE_DESCRIPTION = SERVICE_DESCRIPTIONW if UNICODE else SERVICE_DESCRIPTIONA
LPSERVICE_DESCRIPTION = LPSERVICE_DESCRIPTIONW if UNICODE else LPSERVICE_DESCRIPTIONA

SC_ACTION_NONE = 0
SC_ACTION_RESTART = 1
SC_ACTION_REBOOT = 2
SC_ACTION_RUN_COMMAND = 3

class _SC_ACTION_TYPE(enum.IntFlag):
    SC_ACTION_NONE = 0
    SC_ACTION_RESTART = 1
    SC_ACTION_REBOOT = 2
    SC_ACTION_RUN_COMMAND = 3

SC_ACTION_TYPE = _SC_ACTION_TYPE

class _SC_ACTION(Structure):
    _fields_ = [('Type', UINT),
                ('Delay', DWORD)
    ]

SC_ACTION = _SC_ACTION
LPSC_ACTION = POINTER(SC_ACTION)

class _SERVICE_FAILURE_ACTIONSA(Structure):
    _fields_ = [('dwResetPeriod', DWORD),
                ('lpRebootMsg', LPSTR),
                ('lpCommand', LPSTR),
                ('cActions', DWORD),
                ('lpsaActions', LPSC_ACTION)
    ]

SERVICE_FAILURE_ACTIONSA = _SERVICE_FAILURE_ACTIONSA
LPSERVICE_FAILURE_ACTIONSA = POINTER(SERVICE_FAILURE_ACTIONSA)

class _SERVICE_FAILURE_ACTIONSW(Structure):
    _fields_ = [('dwResetPeriod', DWORD),
                ('lpRebootMsg', LPWSTR),
                ('lpCommand', LPWSTR),
                ('cActions', DWORD),
                ('lpsaActions', LPSC_ACTION)
    ]

SERVICE_FAILURE_ACTIONSW = _SERVICE_FAILURE_ACTIONSW
LPSERVICE_FAILURE_ACTIONSW = POINTER(SERVICE_FAILURE_ACTIONSW)

SERVICE_FAILURE_ACTIONS = SERVICE_FAILURE_ACTIONSW if UNICODE else SERVICE_FAILURE_ACTIONSA
LPSERVICE_FAILURE_ACTIONS = LPSERVICE_FAILURE_ACTIONSW if UNICODE else LPSERVICE_FAILURE_ACTIONSA

LPSC_HANDLE = POINTER(SC_HANDLE)

SC_STATUS_PROCESS_INFO = 0

class _SC_STATUS_TYPE(enum.IntFlag):
    SC_STATUS_PROCESS_INFO = 0

SC_STATUS_TYPE = _SC_STATUS_TYPE

SC_ENUM_PROCESS_INFO = 0

class _SC_ENUM_TYPE(enum.IntFlag):
    SC_ENUM_PROCESS_INFO = 0

SC_ENUM_TYPE = _SC_ENUM_TYPE

class _SERVICE_STATUS(Structure):
    _fields_ = [('dwServiceType', DWORD),
                ('dwCurrentState', DWORD),
                ('dwControlsAccepted', DWORD),
                ('dwWin32ExitCode', DWORD),
                ('dwServiceSpecificExitCode', DWORD),
                ('dwCheckPoint', DWORD),
                ('dwWaitHint', DWORD)
    ]

SERVICE_STATUS = _SERVICE_STATUS
LPSERVICE_STATUS = POINTER(SERVICE_STATUS)

class _SERVICE_STATUS_PROCESS(Structure):
    _fields_ = [('dwServiceType', DWORD),
                ('dwCurrentState', DWORD),
                ('dwControlsAccepted', DWORD),
                ('dwWin32ExitCode', DWORD),
                ('dwServiceSpecificExitCode', DWORD),
                ('dwCheckPoint', DWORD),
                ('dwWaitHint', DWORD),
                ('dwProcessId', DWORD),
                ('dwServiceFlags', DWORD)
    ]

SERVICE_STATUS_PROCESS = _SERVICE_STATUS_PROCESS
LPSERVICE_STATUS_PROCESS = POINTER(SERVICE_STATUS_PROCESS)

class _ENUM_SERVICE_STATUSA(Structure):
    _fields_ = [('lpServiceName', LPSTR),
                ('lpDisplayName', LPSTR),
                ('ServiceStatus', SERVICE_STATUS)
    ]

ENUM_SERVICE_STATUSA = _ENUM_SERVICE_STATUSA
LPENUM_SERVICE_STATUSA = POINTER(ENUM_SERVICE_STATUSA)

class _ENUM_SERVICE_STATUSW(Structure):
    _fields_ = [('lpServiceName', LPWSTR),
                ('lpDisplayName', LPWSTR),
                ('ServiceStatus', SERVICE_STATUS)
    ]

ENUM_SERVICE_STATUSW = _ENUM_SERVICE_STATUSW
LPENUM_SERVICE_STATUSW = POINTER(ENUM_SERVICE_STATUSW)

ENUM_SERVICE_STATUS = ENUM_SERVICE_STATUSW if UNICODE else ENUM_SERVICE_STATUSA
LPENUM_SERVICE_STATUS = LPENUM_SERVICE_STATUSW if UNICODE else LPENUM_SERVICE_STATUSA

class _ENUM_SERVICE_STATUS_PROCESSA(Structure):
    _fields_ = [('lpServiceName', LPSTR),
                ('lpDisplayName', LPSTR),
                ('ServiceStatusProcess', SERVICE_STATUS_PROCESS)
    ]

ENUM_SERVICE_STATUS_PROCESSA = _ENUM_SERVICE_STATUS_PROCESSA
LPENUM_SERVICE_STATUS_PROCESSA = POINTER(ENUM_SERVICE_STATUS_PROCESSA)

class _ENUM_SERVICE_STATUS_PROCESSW(Structure):
    _fields_ = [('lpServiceName', LPWSTR),
                ('lpDisplayName', LPWSTR),
                ('ServiceStatusProcess', SERVICE_STATUS_PROCESS)
    ]

ENUM_SERVICE_STATUS_PROCESSW = _ENUM_SERVICE_STATUS_PROCESSW
LPENUM_SERVICE_STATUS_PROCESSW = POINTER(ENUM_SERVICE_STATUS_PROCESSW)

ENUM_SERVICE_STATUS_PROCESS = ENUM_SERVICE_STATUS_PROCESSW if UNICODE else ENUM_SERVICE_STATUS_PROCESSA
LPENUM_SERVICE_STATUS_PROCESS = LPENUM_SERVICE_STATUS_PROCESSW if UNICODE else LPENUM_SERVICE_STATUS_PROCESSA

class _QUERY_SERVICE_LOCK_STATUSA(Structure):
    _fields_ = [('fIsLocked', DWORD),
                ('lpLockOwner', LPSTR),
                ('dwLockDuration', DWORD)
    ]

QUERY_SERVICE_LOCK_STATUSA = _QUERY_SERVICE_LOCK_STATUSA
LPQUERY_SERVICE_LOCK_STATUSA = POINTER(QUERY_SERVICE_LOCK_STATUSA)

class _QUERY_SERVICE_LOCK_STATUSW(Structure):
    _fields_ = [('fIsLocked', DWORD),
                ('lpLockOwner', LPWSTR),
                ('dwLockDuration', DWORD)
    ]

QUERY_SERVICE_LOCK_STATUSW = _QUERY_SERVICE_LOCK_STATUSW
LPQUERY_SERVICE_LOCK_STATUSW = POINTER(QUERY_SERVICE_LOCK_STATUSW)

QUERY_SERVICE_LOCK_STATUS = QUERY_SERVICE_LOCK_STATUSW if UNICODE else QUERY_SERVICE_LOCK_STATUSA
LPQUERY_SERVICE_LOCK_STATUS = LPQUERY_SERVICE_LOCK_STATUSW if UNICODE else LPQUERY_SERVICE_LOCK_STATUSA

class _QUERY_SERVICE_CONFIGA(Structure):
    _fields_ = [('dwServiceType', DWORD),
                ('dwStartType', DWORD),
                ('dwErrorControl', DWORD),
                ('lpBinaryPathName', LPSTR),
                ('lpLoadOrderGroup', LPSTR),
                ('dwTagId', DWORD),
                ('lpDependencies', LPSTR),
                ('lpServiceStartName', LPSTR),
                ('lpDisplayName', LPSTR)
    ]

QUERY_SERVICE_CONFIGA = _QUERY_SERVICE_CONFIGA
LPQUERY_SERVICE_CONFIGA = POINTER(QUERY_SERVICE_CONFIGA)

class _QUERY_SERVICE_CONFIGW(Structure):
    _fields_ = [('dwServiceType', DWORD),
                ('dwStartType', DWORD),
                ('dwErrorControl', DWORD),
                ('lpBinaryPathName', LPWSTR),
                ('lpLoadOrderGroup', LPWSTR),
                ('dwTagId', DWORD),
                ('lpDependencies', LPWSTR),
                ('lpServiceStartName', LPWSTR),
                ('lpDisplayName', LPWSTR)
    ]

QUERY_SERVICE_CONFIGW = _QUERY_SERVICE_CONFIGW
LPQUERY_SERVICE_CONFIGW = POINTER(QUERY_SERVICE_CONFIGW)

QUERY_SERVICE_CONFIG = QUERY_SERVICE_CONFIGW if UNICODE else QUERY_SERVICE_CONFIGA
LPQUERY_SERVICE_CONFIG = LPQUERY_SERVICE_CONFIGW if UNICODE else LPQUERY_SERVICE_CONFIGA

LPSERVICE_MAIN_FUNCTIONW = WINAPI(VOID, DWORD, LPWSTR)
LPSERVICE_MAIN_FUNCTIONA = WINAPI(VOID, DWORD, LPSTR)

LPSERVICE_MAIN_FUNCTION = LPSERVICE_MAIN_FUNCTIONW if UNICODE else LPSERVICE_MAIN_FUNCTIONA

class _SERVICE_TABLE_ENTRYA(Structure):
    _fields_ = [('lpServiceName', LPSTR),
                ('lpServiceProc', LPSERVICE_MAIN_FUNCTIONA)
    ]

SERVICE_TABLE_ENTRYA = _SERVICE_TABLE_ENTRYA
LPSERVICE_TABLE_ENTRYA = POINTER(SERVICE_TABLE_ENTRYA)

class _SERVICE_TABLE_ENTRYW(Structure):
    _fields_ = [('lpServiceName', LPWSTR),
                ('lpServiceProc', LPSERVICE_MAIN_FUNCTIONW)
    ]

SERVICE_TABLE_ENTRYW = _SERVICE_TABLE_ENTRYW
LPSERVICE_TABLE_ENTRYW = POINTER(SERVICE_TABLE_ENTRYW)

SERVICE_TABLE_ENTRY = SERVICE_TABLE_ENTRYW if UNICODE else SERVICE_TABLE_ENTRYA
LPSERVICE_TABLE_ENTRY = LPSERVICE_TABLE_ENTRYW if UNICODE else LPSERVICE_TABLE_ENTRYA

LPHANDLER_FUNCTION = WINAPI(VOID, DWORD)
LPHANDLER_FUNCTION_EX = WINAPI(DWORD, DWORD, DWORD, LPVOID,LPVOID)


def ChangeServiceConfig(
    hService, 
    dwServiceType, 
    dwStartType, 
    dwErrorControl, 
    lpBinaryPathName, 
    lpLoadOrderGroup, 
    lpdwTagId, 
    lpDependencies, 
    lpServiceStartName, 
    lpPassword, 
    lpDisplayName, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    ChangeServiceConfig = (advapi32.ChangeServiceConfigW 
                           if unicode else advapi32.ChangeServiceConfigA
    )

    ChangeServiceConfig.argtypes = [
        SC_HANDLE, 
        DWORD, 
        DWORD, 
        DWORD, 
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        LPDWORD,
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR)
    ]

    ChangeServiceConfig.restype = WINBOOL
    res = ChangeServiceConfig(
        hService, 
        dwServiceType, 
        dwStartType, 
        dwErrorControl, 
        lpBinaryPathName, 
        lpLoadOrderGroup, 
        lpdwTagId, 
        lpDependencies, 
        lpServiceStartName, 
        lpPassword, 
        lpDisplayName
    )

    return win32_to_errcheck(res, errcheck)    


def ChangeServiceConfig2(hService, dwInfoLevel, lpInfo, unicode: bool = True, errcheck: bool = True):
    ChangeServiceConfig2 = (advapi32.ChangeServiceConfig2W 
                            if unicode else advapi32.ChangeServiceConfig2A
    )
    
    ChangeServiceConfig2.argtypes = [SC_HANDLE, DWORD, LPVOID]
    ChangeServiceConfig2.restype = WINBOOL
    res = ChangeServiceConfig2(hService, dwInfoLevel, lpInfo)
    return win32_to_errcheck(res, errcheck)    


def CloseServiceHandle(hSCObject, errcheck: bool = True):
    CloseServiceHandle = advapi32.CloseServiceHandle
    CloseServiceHandle.argtypes = [SC_HANDLE]
    CloseServiceHandle.restype = WINBOOL
    res = CloseServiceHandle(hSCObject)
    return win32_to_errcheck(res, errcheck)    


def ControlService(hService, dwControl, lpServiceStatus, errcheck: bool = True):
    ControlService = advapi32.ControlService
    ControlService.argtypes = [SC_HANDLE, DWORD, LPSERVICE_STATUS]
    ControlService.restype = WINBOOL
    res = ControlService(hService, dwControl, lpServiceStatus)
    return win32_to_errcheck(res, errcheck)


def CreateService(
    hSCManager, 
    lpServiceName, 
    lpDisplayName, 
    dwDesiredAccess, 
    dwServiceType, 
    dwStartType, 
    dwErrorControl, 
    lpBinaryPathName, 
    lpLoadOrderGroup, 
    lpdwTagId, 
    lpDependencies, 
    lpServiceStartName, 
    lpPassword, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    CreateService = advapi32.CreateServiceW if unicode else advapi32.CreateServiceA
    CreateService.argtypes = [
        SC_HANDLE, 
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        DWORD,
        DWORD,
        DWORD,
        DWORD, 
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        LPDWORD,
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR)
    ]

    CreateService.restype = SC_HANDLE
    res = CreateService(
        hSCManager, 
        lpServiceName, 
        lpDisplayName, 
        dwDesiredAccess, 
        dwServiceType, 
        dwStartType, 
        dwErrorControl, 
        lpBinaryPathName, 
        lpLoadOrderGroup, 
        lpdwTagId, 
        lpDependencies, 
        lpServiceStartName, 
        lpPassword
    )

    return win32_to_errcheck(res, errcheck)    



def DeleteService(hService, errcheck: bool = True):
    DeleteService = advapi32.DeleteService
    DeleteService.argtypes = [SC_HANDLE]
    DeleteService.restype = WINBOOL
    res = DeleteService(hService)
    return win32_to_errcheck(res, errcheck)    


def EnumDependentServices(
    hService, 
    dwServiceState, 
    lpServices, 
    cbBufSize, 
    pcbBytesNeeded, 
    lpServicesReturned, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    EnumDependentServices = (advapi32.EnumDependentServicesW 
                             if unicode else advapi32.EnumDependentServicesA
    )

    EnumDependentServices.argtypes = [
        SC_HANDLE, 
        DWORD, 
        (LPENUM_SERVICE_STATUSW if unicode else LPENUM_SERVICE_STATUSA),
        DWORD,
        LPDWORD,
        LPDWORD
    ]

    EnumDependentServices.restype = WINBOOL
    res = EnumDependentServices(
        hService, 
        dwServiceState, 
        lpServices, 
        cbBufSize, 
        pcbBytesNeeded, 
        lpServicesReturned
    )

    return win32_to_errcheck(res, errcheck)    


def EnumServicesStatus(
    hSCManager, 
    dwServiceType, 
    dwServiceState, 
    lpServices, 
    cbBufSize, 
    pcbBytesNeeded, 
    lpServicesReturned, 
    lpResumeHandle, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    EnumServicesStatus = advapi32.EnumServicesStatusW if unicode else advapi32.EnumServicesStatusA
    EnumServicesStatus.argtypes = [
        SC_HANDLE, 
        DWORD,
        DWORD,
        (LPENUM_SERVICE_STATUSW if unicode else LPENUM_SERVICE_STATUSA),
        DWORD,
        LPDWORD,
        LPDWORD,
        LPDWORD
    ]

    EnumServicesStatus.restype = WINBOOL
    res = EnumServicesStatus(
        hSCManager, 
        dwServiceType, 
        dwServiceState, 
        lpServices, 
        cbBufSize, 
        pcbBytesNeeded, 
        lpServicesReturned, 
        lpResumeHandle
    )

    return win32_to_errcheck(res, errcheck)    


def EnumServicesStatusEx(
    hSCManager, 
    dwServiceType, 
    dwServiceState, 
    lpServices, 
    cbBufSize, 
    pcbBytesNeeded, 
    lpServicesReturned, 
    lpResumeHandle, 
    pszGroupName, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    EnumServicesStatusEx = (advapi32.EnumServicesStatusExW 
                            if unicode else advapi32.EnumServicesStatusExA
    )

    EnumServicesStatusEx.restype = WINBOOL
    EnumServicesStatusEx.argtypes = [
        SC_HANDLE, 
        UINT, 
        DWORD,
        DWORD,
        LPBYTE,
        DWORD,
        LPDWORD,
        LPDWORD,
        LPDWORD,
        (LPCWSTR if unicode else LPCSTR)
    ]

    res = EnumServicesStatusEx(
        hSCManager, 
        dwServiceType, 
        dwServiceState, 
        lpServices, 
        cbBufSize, 
        pcbBytesNeeded, 
        lpServicesReturned, 
        lpResumeHandle, 
        pszGroupName
    )

    return win32_to_errcheck(res, errcheck)    


def GetServiceKeyName(
    hSCManager, 
    lpDisplayName, 
    lpServiceName, 
    lpcchBuffer, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    GetServiceKeyName = (advapi32.GetServiceKeyNameW 
                         if unicode else advapi32.GetServiceKeyNameA
    )

    GetServiceKeyName.argtypes = [
        SC_HANDLE,
        (LPCWSTR if unicode else LPCSTR),
        (LPWSTR if unicode else LPSTR),
        LPDWORD
    ]

    GetServiceKeyName.restype = WINBOOL
    res = GetServiceKeyName(
        hSCManager, 
        lpDisplayName, 
        lpServiceName, 
        lpcchBuffer
    )

    return win32_to_errcheck(res, errcheck)    


def GetServiceDisplayName(
    hSCManager, 
    lpServiceName, 
    lpDisplayName, 
    lpcchBuffer, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    GetServiceDisplayName = (advapi32.GetServiceDisplayNameW 
                             if unicode else advapi32.GetServiceDisplayNameA
    )

    GetServiceDisplayName.argtypes = [
        SC_HANDLE,
        (LPCWSTR if unicode else LPCSTR),
        (LPWSTR if unicode else LPSTR),
        LPDWORD
    ]

    GetServiceDisplayName.restype = WINBOOL
    res = GetServiceDisplayName(
        hSCManager, 
        lpServiceName, 
        lpDisplayName, 
        lpcchBuffer
    )

    return win32_to_errcheck(res, errcheck)    


def LockServiceDatabase(hSCManager, errcheck: bool = True):
    LockServiceDatabase = advapi32.LockServiceDatabase
    LockServiceDatabase.restype = SC_LOCK
    res = LockServiceDatabase(hSCManager)
    return win32_to_errcheck(res, errcheck)    



def NotifyBootConfigStatus(BootAcceptable, errcheck: bool = True):
    NotifyBootConfigStatus = advapi32.NotifyBootConfigStatus
    NotifyBootConfigStatus.argtypes = [WINBOOL]
    NotifyBootConfigStatus.restype = SC_LOCK
    res = NotifyBootConfigStatus(BootAcceptable)
    return win32_to_errcheck(res, errcheck)    


def OpenSCManager(
    lpMachineName: str | bytes, 
    lpDatabaseName: str | bytes, 
    dwDesiredAccess: int, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    OpenSCManager = advapi32.OpenSCManagerW if unicode else advapi32.OpenSCManagerA
    OpenSCManager.argtypes = [
        (LPCWSTR if unicode else LPCSTR),
        (LPCWSTR if unicode else LPCSTR),
        DWORD
    ]

    OpenSCManager.restype = SC_HANDLE
    res = OpenSCManager(
        lpMachineName, 
        lpDatabaseName, 
        dwDesiredAccess
    )

    return win32_to_errcheck(res, errcheck)    



def OpenService(
    hSCManager, 
    lpServiceName, 
    dwDesiredAccess, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    OpenService = advapi32.OpenServiceW if unicode else advapi32.OpenServiceA
    OpenService.argtypes = [
        SC_HANDLE, 
        (LPCWSTR if unicode else LPCSTR),
        DWORD
    ]

    OpenService.restype = SC_HANDLE
    res = OpenService(
        hSCManager, 
        lpServiceName, 
        dwDesiredAccess
    )
    
    return win32_to_errcheck(res, errcheck)    
    


def QueryServiceConfig(
    hService, 
    lpServiceConfig, 
    cbBufSize, 
    pcbBytesNeeded, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    QueryServiceConfig = (advapi32.QueryServiceConfigW 
                          if unicode else advapi32.QueryServiceConfigA
    )

    QueryServiceConfig.argtypes = [
        SC_HANDLE,
        (LPQUERY_SERVICE_CONFIGW if unicode else LPQUERY_SERVICE_CONFIGA),
        DWORD,
        LPDWORD
    ]

    QueryServiceConfig.restype = WINBOOL
    res = QueryServiceConfig(
        hService, 
        lpServiceConfig, 
        cbBufSize, 
        pcbBytesNeeded
    )

    return win32_to_errcheck(res, errcheck)    


def QueryServiceConfig2(
    hService, 
    dwInfoLevel, 
    lpBuffer, 
    cbBufSize, 
    pcbBytesNeeded, 
    unicode: bool = True,
    errcheck: bool = True
):
    
    QueryServiceConfig2 = (advapi32.QueryServiceConfig2W 
                           if unicode else advapi32.QueryServiceConfig2A
    )

    QueryServiceConfig2.argtypes = [
        SC_HANDLE,
        DWORD,
        LPBYTE,
        DWORD,
        LPDWORD
    ]

    QueryServiceConfig2.restype = WINBOOL
    res = QueryServiceConfig2(
        hService, 
        dwInfoLevel, 
        lpBuffer, 
        cbBufSize, 
        pcbBytesNeeded
    )

    return win32_to_errcheck(res, errcheck)    


def QueryServiceLockStatus(hSCManager, lpLockStatus, cbBufSize, pcbBytesNeeded, unicode: bool = True, errcheck: bool = True):
    QueryServiceLockStatus = advapi32.QueryServiceLockStatusW if unicode else advapi32.QueryServiceLockStatusA
    QueryServiceLockStatus.argtypes = [
        SC_HANDLE,
        (LPQUERY_SERVICE_CONFIGW if unicode else LPQUERY_SERVICE_CONFIGA),
        DWORD,
        LPDWORD
    ]

    QueryServiceLockStatus.restype = WINBOOL
    res = QueryServiceLockStatus(hSCManager, lpLockStatus, cbBufSize, pcbBytesNeeded)
    return win32_to_errcheck(res, errcheck)    


def QueryServiceObjectSecurity(hService, dwSecurityInformation, lpSecurityDescriptor, cbBufSize, pcbBytesNeeded, errcheck: bool = True):
    QueryServiceObjectSecurity = advapi32.QueryServiceObjectSecurity
    QueryServiceObjectSecurity.argtypes = [
        SC_HANDLE,
        SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
        DWORD,
        LPDWORD
    ]

    QueryServiceObjectSecurity.restype = WINBOOL
    res = QueryServiceObjectSecurity(hService, dwSecurityInformation, lpSecurityDescriptor, cbBufSize, pcbBytesNeeded)
    return win32_to_errcheck(res, errcheck)    


def QueryServiceStatus(hService, lpServiceStatus, errcheck: bool = True):
    QueryServiceStatus = advapi32.QueryServiceStatus
    QueryServiceStatus.argtypes = [SC_HANDLE, LPSERVICE_STATUS]
    QueryServiceStatus.restype = WINBOOL
    res = QueryServiceStatus(hService, lpServiceStatus)
    return win32_to_errcheck(res, errcheck)    


def QueryServiceStatusEx(
    hService, 
    InfoLevel, 
    lpBuffer, 
    cbBufSize, 
    pcbBytesNeeded,
    errcheck: bool = True
):
    
    QueryServiceStatusEx = advapi32.QueryServiceStatusEx
    QueryServiceStatusEx.argtypes = [
        SC_HANDLE, 
        UINT,
        LPBYTE,
        DWORD,
        LPDWORD
    ]
    
    QueryServiceStatusEx.restype = WINBOOL
    res = QueryServiceStatusEx(
        hService, 
        InfoLevel, 
        lpBuffer, 
        cbBufSize, 
        pcbBytesNeeded
    )

    return win32_to_errcheck(res, errcheck)    


def RegisterServiceCtrlHandler(lpServiceName, lpHandlerProc, unicode: bool = True, errcheck: bool = True):
    RegisterServiceCtrlHandler = (advapi32.RegisterServiceCtrlHandlerW 
                                  if unicode else advapi32.RegisterServiceCtrlHandlerA
    )

    RegisterServiceCtrlHandler.argtypes = [
        (LPCWSTR if unicode else LPCSTR),
        LPHANDLER_FUNCTION
    ]

    RegisterServiceCtrlHandler.restype = SERVICE_STATUS_HANDLE
    res = RegisterServiceCtrlHandler(lpServiceName, lpHandlerProc)
    return win32_to_errcheck(res, errcheck)    



def RegisterServiceCtrlHandlerEx(lpServiceName, lpHandlerProc, lpContext, unicode: bool = True, errcheck: bool = True):
    RegisterServiceCtrlHandlerEx = (advapi32.RegisterServiceCtrlHandlerExW 
                                    if unicode else advapi32.RegisterServiceCtrlHandlerExA
    )

    RegisterServiceCtrlHandlerEx.argtypes = [
        (LPCWSTR if unicode else LPCSTR),
        LPHANDLER_FUNCTION_EX,
        LPVOID
    ]

    RegisterServiceCtrlHandlerEx.restype = SERVICE_STATUS_HANDLE
    res = RegisterServiceCtrlHandlerEx(lpServiceName, lpHandlerProc, lpContext)
    return win32_to_errcheck(res, errcheck)    



def SetServiceObjectSecurity(hService, dwSecurityInformation, lpSecurityDescriptor, errcheck: bool = True):
    SetServiceObjectSecurity = advapi32.SetServiceObjectSecurity
    SetServiceObjectSecurity.argtypes = [
        SC_HANDLE,
        SECURITY_INFORMATION,
        PSECURITY_INFORMATION
    ]

    SetServiceObjectSecurity.restype = WINBOOL
    res = SetServiceObjectSecurity(hService, dwSecurityInformation, lpSecurityDescriptor)
    return win32_to_errcheck(res, errcheck)    


def SetServiceStatus(hServiceStatus, lpServiceStatus, errcheck: bool = True):
    SetServiceStatus = advapi32.SetServiceStatus
    SetServiceStatus.argtypes = [
        SERVICE_STATUS_HANDLE,
        LPENUM_SERVICE_STATUS
    ]

    SetServiceStatus.restype = WINBOOL
    res = SetServiceStatus(hServiceStatus, lpServiceStatus)
    return win32_to_errcheck(res, errcheck)    


def StartServiceCtrlDispatcher(lpServiceStartTable, unicode: bool = True, errcheck: bool = True):
    StartServiceCtrlDispatcher = (advapi32.StartServiceCtrlDispatcherW 
                                  if unicode else advapi32.StartServiceCtrlDispatcherA
    )

    StartServiceCtrlDispatcher.argtypes = [(SERVICE_TABLE_ENTRYW if unicode else SERVICE_TABLE_ENTRYA)]
    StartServiceCtrlDispatcher.restype = WINBOOL
    res = StartServiceCtrlDispatcher(lpServiceStartTable)
    return win32_to_errcheck(res, errcheck)    


def StartService(hService, dwNumServiceArgs, lpServiceArgVectors, unicode: bool = True, errcheck: bool = True):
    StartService = advapi32.StartServiceW if unicode else advapi32.StartServiceA
    StartService.argtypes = [
        SC_HANDLE, 
        DWORD, 
        (LPCWSTR if unicode else LPCSTR)
    ]

    StartService.restype = WINBOOL
    res = StartService(hService, dwNumServiceArgs, lpServiceArgVectors)
    return win32_to_errcheck(res, errcheck)    


def UnlockServiceDatabase(ScLock, errcheck: bool = True):
    UnlockServiceDatabase = advapi32.UnlockServiceDatabase
    UnlockServiceDatabase.argtypes = [SC_LOCK]
    UnlockServiceDatabase.restype = WINBOOL
    res = UnlockServiceDatabase(ScLock)
    return win32_to_errcheck(res, errcheck)    


PFN_SC_NOTIFY_CALLBACK = CALLBACK(VOID, PVOID)

class _SERVICE_CONTROL_STATUS_REASON_PARAMSA(Structure):
    _fields_ = [('dwReason', DWORD),
                ('pszComment', LPSTR),
                ('ServiceStatus', SERVICE_STATUS_PROCESS)
    ]

SERVICE_CONTROL_STATUS_REASON_PARAMSA = _SERVICE_CONTROL_STATUS_REASON_PARAMSA
PSERVICE_CONTROL_STATUS_REASON_PARAMSA = POINTER(SERVICE_CONTROL_STATUS_REASON_PARAMSA)

class _SERVICE_CONTROL_STATUS_REASON_PARAMSW(Structure):
    _fields_ = [('dwReason', DWORD),
                ('pszComment', LPWSTR),
                ('ServiceStatus', SERVICE_STATUS_PROCESS)
    ]

SERVICE_CONTROL_STATUS_REASON_PARAMSW = _SERVICE_CONTROL_STATUS_REASON_PARAMSW
PSERVICE_CONTROL_STATUS_REASON_PARAMSW = POINTER(SERVICE_CONTROL_STATUS_REASON_PARAMSW)

SERVICE_CONTROL_STATUS_REASON_PARAMS = SERVICE_CONTROL_STATUS_REASON_PARAMSW if UNICODE else SERVICE_CONTROL_STATUS_REASON_PARAMSA
PSERVICE_CONTROL_STATUS_REASON_PARAMS = PSERVICE_CONTROL_STATUS_REASON_PARAMSW if UNICODE else PSERVICE_CONTROL_STATUS_REASON_PARAMSA

SERVICE_STOP_REASON_FLAG_CUSTOM = 0x20000000
SERVICE_STOP_REASON_FLAG_PLANNED = 0x40000000
SERVICE_STOP_REASON_FLAG_UNPLANNED = 0x10000000

SERVICE_STOP_REASON_MAJOR_APPLICATION = 0x00050000
SERVICE_STOP_REASON_MAJOR_HARDWARE = 0x00020000
SERVICE_STOP_REASON_MAJOR_NONE = 0x00060000
SERVICE_STOP_REASON_MAJOR_OPERATINGSYSTEM = 0x00030000
SERVICE_STOP_REASON_MAJOR_OTHER = 0x00010000
SERVICE_STOP_REASON_MAJOR_SOFTWARE = 0x00040000

SERVICE_STOP_REASON_MINOR_DISK = 0x00000008
SERVICE_STOP_REASON_MINOR_ENVIRONMENT = 0x0000000a
SERVICE_STOP_REASON_MINOR_HARDWARE_DRIVER = 0x0000000b
SERVICE_STOP_REASON_MINOR_HUNG = 0x00000006
SERVICE_STOP_REASON_MINOR_INSTALLATION = 0x00000003
SERVICE_STOP_REASON_MINOR_MAINTENANCE = 0x00000002
SERVICE_STOP_REASON_MINOR_MMC = 0x00000016
SERVICE_STOP_REASON_MINOR_NETWORK_CONNECTIVITY = 0x00000011
SERVICE_STOP_REASON_MINOR_NETWORKCARD = 0x00000009
SERVICE_STOP_REASON_MINOR_OTHER = 0x00000001
SERVICE_STOP_REASON_MINOR_OTHERDRIVER = 0x0000000c
SERVICE_STOP_REASON_MINOR_RECONFIG = 0x00000005
SERVICE_STOP_REASON_MINOR_SECURITY = 0x00000010
SERVICE_STOP_REASON_MINOR_SECURITYFIX = 0x0000000f
SERVICE_STOP_REASON_MINOR_SECURITYFIX_UNINSTALL = 0x00000015
SERVICE_STOP_REASON_MINOR_SERVICEPACK = 0x0000000d
SERVICE_STOP_REASON_MINOR_SERVICEPACK_UNINSTALL = 0x00000013
SERVICE_STOP_REASON_MINOR_SOFTWARE_UPDATE = 0x0000000e
SERVICE_STOP_REASON_MINOR_UNSTABLE = 0x00000007
SERVICE_STOP_REASON_MINOR_UPGRADE = 0x00000004
SERVICE_STOP_REASON_MINOR_WMI = 0x00000012

class _SERVICE_NOTIFYA(Structure):
    _fields_ = [('dwVersion', DWORD),
                ('pfnNotifyCallback', PFN_SC_NOTIFY_CALLBACK),
                ('pContext', PVOID),
                ('dwNotificationStatus', DWORD),
                ('ServiceStatus', SERVICE_STATUS_PROCESS),
                ('dwNotificationTriggered', DWORD),
                ('pszServiceNames', LPSTR)
    ]

SERVICE_NOTIFYA = _SERVICE_NOTIFYA
PSERVICE_NOTIFYA = POINTER(SERVICE_NOTIFYA)

class _SERVICE_NOTIFYW(Structure):
    _fields_ = [('dwVersion', DWORD),
                ('pfnNotifyCallback', PFN_SC_NOTIFY_CALLBACK),
                ('pContext', PVOID),
                ('dwNotificationStatus', DWORD),
                ('ServiceStatus', SERVICE_STATUS_PROCESS),
                ('dwNotificationTriggered', DWORD),
                ('pszServiceNames', LPWSTR)
    ]

SERVICE_NOTIFYW = _SERVICE_NOTIFYW
PSERVICE_NOTIFYW = POINTER(SERVICE_NOTIFYW)

SERVICE_NOTIFY = SERVICE_NOTIFYW if UNICODE else SERVICE_NOTIFYA
PSERVICE_NOTIFY = PSERVICE_NOTIFYW if UNICODE else PSERVICE_NOTIFYA

SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3
SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4
SERVICE_CONFIG_SERVICE_SID_INFO = 5
SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 6
SERVICE_CONFIG_PRESHUTDOWN_INFO = 7

class _SERVICE_DELAYED_AUTO_START_INFO(Structure):
    _fields_ = [('fDelayedAutostart', WINBOOL)]

SERVICE_DELAYED_AUTO_START_INFO = _SERVICE_DELAYED_AUTO_START_INFO
LPSERVICE_DELAYED_AUTO_START_INFO = POINTER(SERVICE_DELAYED_AUTO_START_INFO)

class _SERVICE_FAILURE_ACTIONS_FLAG(Structure):
    _fields_ = [('fFailureActionsOnNonCrashFailures', WINBOOL)]

SERVICE_FAILURE_ACTIONS_FLAG = _SERVICE_FAILURE_ACTIONS_FLAG
LPSERVICE_FAILURE_ACTIONS_FLAG = POINTER(SERVICE_FAILURE_ACTIONS_FLAG)

class _SERVICE_PRESHUTDOWN_INFO(Structure):
    _fields_ = [('dwPreshutdownTimeout', DWORD)]

SERVICE_PRESHUTDOWN_INFO = _SERVICE_PRESHUTDOWN_INFO
LPSERVICE_PRESHUTDOWN_INFO = POINTER(SERVICE_PRESHUTDOWN_INFO)

class _SERVICE_REQUIRED_PRIVILEGES_INFOA(Structure):
    _fields_ = [('pmszRequiredPrivileges', LPSTR)]

SERVICE_REQUIRED_PRIVILEGES_INFOA = _SERVICE_REQUIRED_PRIVILEGES_INFOA
LPSERVICE_REQUIRED_PRIVILEGES_INFOA =  POINTER(SERVICE_REQUIRED_PRIVILEGES_INFOA)

class _SERVICE_REQUIRED_PRIVILEGES_INFOW(Structure):
    _fields_ = [('pmszRequiredPrivileges', LPWSTR)]

SERVICE_REQUIRED_PRIVILEGES_INFOW = _SERVICE_REQUIRED_PRIVILEGES_INFOW
LPSERVICE_REQUIRED_PRIVILEGES_INFOW = POINTER(SERVICE_REQUIRED_PRIVILEGES_INFOW)

SERVICE_REQUIRED_PRIVILEGES_INFO = SERVICE_REQUIRED_PRIVILEGES_INFOW if UNICODE else SERVICE_REQUIRED_PRIVILEGES_INFOA

SERVICE_SID_TYPE_NONE = 0x00000000
SERVICE_SID_TYPE_RESTRICTED = 0x00000003
SERVICE_SID_TYPE_UNRESTRICTED = 0x00000001

class _SERVICE_SID_INFO(Structure):
    _fields_ = [('dwServiceSidType', DWORD)]

SERVICE_SID_INFO = _SERVICE_SID_INFO
LPSERVICE_SID_INFO = POINTER(SERVICE_SID_INFO)



def ControlServiceEx(hService, dwControl, dwInfoLevel, pControlParams, unicode: bool = True, errcheck: bool = True):
    ControlServiceEx = advapi32.ControlServiceExW if unicode else advapi32.ControlServiceExA
    ControlServiceEx.argtypes = [
        SC_HANDLE,
        DWORD,
        DWORD,
        PVOID
    ]

    ControlServiceEx.restype = WINBOOL
    res = ControlServiceEx(hService, dwControl, dwInfoLevel, pControlParams)
    return win32_to_errcheck(res, errcheck)    


def NotifyServiceStatusChange(hService, dwNotifyMask, pNotifyBuffer, unicode: bool = True, errcheck: bool = True):
    NotifyServiceStatusChange = (advapi32.NotifyServiceStatusChangeW 
                                 if unicode else advapi32.NotifyServiceStatusChangeA
    )

    NotifyServiceStatusChange.argtypes = [SC_HANDLE, DWORD]
    NotifyServiceStatusChange.restype = DWORD
    res = NotifyServiceStatusChange(hService, dwNotifyMask, pNotifyBuffer)
    return win32_to_errcheck(res, errcheck)