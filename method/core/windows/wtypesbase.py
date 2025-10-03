# coding = 'utf-8'
# wtypesbase.h

import enum
from typing import Any
from ctypes import POINTER, Union, Structure

try:
    from public_dll import *
    from win_cbasictypes import *
    from sdkddkver import UNICODE
    from guiddef import GUID, IID, CLSID
except ImportError:
    from .public_dll import *
    from .win_cbasictypes import *
    from .sdkddkver import UNICODE
    from .guiddef import GUID, IID, CLSID

hyper = DOUBLE

OLECHAR = WCHAR if UNICODE else CHAR
LPOLESTR = POINTER(OLECHAR if UNICODE else LPSTR)
LPCOLESTR = POINTER(OLECHAR if UNICODE else LPCSTR)

def OLESTR(Str: Any) -> str:
    return str(Str)


class _LARGE_INTEGER(Structure):
    _fields_ = [('QuadPart', LONGLONG)]

LARGE_INTEGER = _LARGE_INTEGER
PLARGE_INTEGER = POINTER(LARGE_INTEGER)

class _ULARGE_INTEGER(Structure):
    _fields_ = [('QuadPart', ULONGLONG)]

ULARGE_INTEGER = _ULARGE_INTEGER

class _FILETIME(Structure):
    _fields_ = [('dwLowDateTime', DWORD),
                ('dwHighDateTime', DWORD)
    ]

FILETIME = _FILETIME
PFILETIME = POINTER(FILETIME)
LPFILETIME = PFILETIME

class _SYSTEMTIME(Structure):
    _fields_ = [('wYear', WORD),
                ('wMonth', WORD),
                ('wDayOfWeek', WORD),
                ('wDay', WORD),
                ('wHour', WORD),
                ('wMinute', WORD),
                ('wSecond', WORD),
                ('wMilliseconds', WORD)
    ]

SYSTEMTIME = _SYSTEMTIME
PSYSTEMTIME = POINTER(SYSTEMTIME)
LPSYSTEMTIME = PSYSTEMTIME

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [('nLength', DWORD),
                ('lpSecurityDescriptor', LPVOID),
                ('bInheritHandle', WINBOOL)
    ]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
PSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)
LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)

SECURITY_DESCRIPTOR_CONTROL = USHORT
PSECURITY_DESCRIPTOR_CONTROL = POINTER(USHORT)

PSID = PVOID

class _ACL(Structure):
    _fields_ = [('AclRevision', BYTE),
                ('Sbz1', BYTE),
                ('AclSize', WORD),
                ('AceCount', WORD),
                ('Sbz2', WORD)
    ]

ACL = _ACL
PACL = POINTER(ACL)

class _SECURITY_DESCRIPTOR(Structure):
    _fields_ = [('Revision', BYTE),
                ('Sbz1', BYTE),
                ('Control', SECURITY_DESCRIPTOR_CONTROL),
                ('Owner', DWORD),
                ('Group', DWORD),
                ('Sacl', DWORD),
                ('Dacl', DWORD)
    ]

SECURITY_DESCRIPTOR = _SECURITY_DESCRIPTOR
PISECURITY_DESCRIPTOR = POINTER(SECURITY_DESCRIPTOR)

class _COAUTHIDENTITY(Structure):
    _fields_ = [('*User', USHORT),
                ('UserLength', ULONG),
                ('Domain', PUSHORT),
                ('DomainLength', ULONG),
                ('Password', PUSHORT),
                ('PasswordLength', ULONG),
                ('Flags', ULONG),
    ]

COAUTHIDENTITY = _COAUTHIDENTITY

class _COAUTHINFO(Structure):
    _fields_ = [('dwAuthnSvc', DWORD),
                ('dwAuthzSvc', DWORD),
                ('pwszServerPrincName', LPWSTR),
                ('dwAuthnLevel', DWORD),
                ('dwImpersonationLevel', DWORD),
                ('pAuthIdentityData', POINTER(COAUTHIDENTITY)),
                ('dwCapabilities', DWORD)
    ]

COAUTHINFO = _COAUTHINFO

SCODE = LONG
PSCODE = POINTER(SCODE)

class _OBJECTID(Structure):
    _fields_ = [('Lineage', GUID),
                ('Uniquifier', DWORD)
    ]

OBJECTID = _OBJECTID

REFGUID = POINTER(GUID)
REFIID = POINTER(IID)
REFCLSID = POINTER(CLSID)

MEMCTX_TASK = 1
MEMCTX_SHARED = 2
MEMCTX_MACSYSTEM = 3
MEMCTX_UNKNOWN = -1
MEMCTX_SAME = -2

class tagMEMCTX(enum.IntFlag):
    MEMCTX_TASK = 1
    MEMCTX_SHARED = 2
    MEMCTX_MACSYSTEM = 3
    MEMCTX_UNKNOWN = -1
    MEMCTX_SAME = -2

MEMCTX = tagMEMCTX

ROTREGFLAGS_ALLOWANYCLIENT = 0x1

APPIDREGFLAGS_ACTIVATE_IUSERVER_INDESKTOP = 0x1
APPIDREGFLAGS_SECURE_SERVER_PROCESS_SD_AND_BIND = 0x2
APPIDREGFLAGS_ISSUE_ACTIVATION_RPC_AT_IDENTIFY = 0x4
APPIDREGFLAGS_IUSERVER_UNMODIFIED_LOGON_TOKEN = 0x8
APPIDREGFLAGS_IUSERVER_SELF_SID_IN_LAUNCH_PERMISSION = 0x10
APPIDREGFLAGS_IUSERVER_ACTIVATE_IN_CLIENT_SESSION_ONLY = 0x20
APPIDREGFLAGS_RESERVED1 = 0x40

DCOMSCM_ACTIVATION_USE_ALL_AUTHNSERVICES = 0x1
DCOMSCM_ACTIVATION_DISALLOW_UNSECURE_CALL = 0x2
DCOMSCM_RESOLVE_USE_ALL_AUTHNSERVICES = 0x4
DCOMSCM_RESOLVE_DISALLOW_UNSECURE_CALL = 0x8
DCOMSCM_PING_USE_MID_AUTHNSERVICE = 0x10
DCOMSCM_PING_DISALLOW_UNSECURE_CALL = 0x20

CLSCTX_INPROC_SERVER = 0x1
CLSCTX_INPROC_HANDLER = 0x2
CLSCTX_LOCAL_SERVER = 0x4
CLSCTX_INPROC_SERVER16 = 0x8
CLSCTX_REMOTE_SERVER = 0x10
CLSCTX_INPROC_HANDLER16 = 0x20
CLSCTX_RESERVED1 = 0x40
CLSCTX_RESERVED2 = 0x80
CLSCTX_RESERVED3 = 0x100
CLSCTX_RESERVED4 = 0x200
CLSCTX_NO_CODE_DOWNLOAD = 0x400
CLSCTX_RESERVED5 = 0x800
CLSCTX_NO_CUSTOM_MARSHAL = 0x1000
CLSCTX_ENABLE_CODE_DOWNLOAD = 0x2000
CLSCTX_NO_FAILURE_LOG = 0x4000
CLSCTX_DISABLE_AAA = 0x8000
CLSCTX_ENABLE_AAA = 0x10000
CLSCTX_FROM_DEFAULT_CONTEXT = 0x20000
CLSCTX_ACTIVATE_32_BIT_SERVER = 0x40000
CLSCTX_ACTIVATE_64_BIT_SERVER = 0x80000
CLSCTX_ENABLE_CLOAKING = 0x100000
CLSCTX_APPCONTAINER = 0x400000
CLSCTX_ACTIVATE_AAA_AS_IU = 0x800000
CLSCTX_PS_DLL = 0x80000000

class tagCLSCTX(enum.IntFlag):
    CLSCTX_INPROC_SERVER = 0x1
    CLSCTX_INPROC_HANDLER = 0x2
    CLSCTX_LOCAL_SERVER = 0x4
    CLSCTX_INPROC_SERVER16 = 0x8
    CLSCTX_REMOTE_SERVER = 0x10
    CLSCTX_INPROC_HANDLER16 = 0x20
    CLSCTX_RESERVED1 = 0x40
    CLSCTX_RESERVED2 = 0x80
    CLSCTX_RESERVED3 = 0x100
    CLSCTX_RESERVED4 = 0x200
    CLSCTX_NO_CODE_DOWNLOAD = 0x400
    CLSCTX_RESERVED5 = 0x800
    CLSCTX_NO_CUSTOM_MARSHAL = 0x1000
    CLSCTX_ENABLE_CODE_DOWNLOAD = 0x2000
    CLSCTX_NO_FAILURE_LOG = 0x4000
    CLSCTX_DISABLE_AAA = 0x8000
    CLSCTX_ENABLE_AAA = 0x10000
    CLSCTX_FROM_DEFAULT_CONTEXT = 0x20000
    CLSCTX_ACTIVATE_32_BIT_SERVER = 0x40000
    CLSCTX_ACTIVATE_64_BIT_SERVER = 0x80000
    CLSCTX_ENABLE_CLOAKING = 0x100000
    CLSCTX_APPCONTAINER = 0x400000
    CLSCTX_ACTIVATE_AAA_AS_IU = 0x800000
    CLSCTX_PS_DLL = 0x80000000

CLSCTX = tagCLSCTX

CLSCTX_VALID_MASK = (CLSCTX_INPROC_SERVER | 
                     CLSCTX_INPROC_HANDLER | 
                     CLSCTX_LOCAL_SERVER | 
                     CLSCTX_INPROC_SERVER16 | 
                     CLSCTX_REMOTE_SERVER | 
                     CLSCTX_NO_CODE_DOWNLOAD | 
                     CLSCTX_NO_CUSTOM_MARSHAL | 
                     CLSCTX_ENABLE_CODE_DOWNLOAD | 
                     CLSCTX_NO_FAILURE_LOG | 
                     CLSCTX_DISABLE_AAA | 
                     CLSCTX_ENABLE_AAA | 
                     CLSCTX_FROM_DEFAULT_CONTEXT | 
                     CLSCTX_ACTIVATE_32_BIT_SERVER | 
                     CLSCTX_ACTIVATE_64_BIT_SERVER | 
                     CLSCTX_ENABLE_CLOAKING | 
                     CLSCTX_APPCONTAINER | 
                     CLSCTX_ACTIVATE_AAA_AS_IU | 
                     CLSCTX_PS_DLL
)

MSHLFLAGS_NORMAL = 0
MSHLFLAGS_TABLESTRONG = 1
MSHLFLAGS_TABLEWEAK = 2
MSHLFLAGS_NOPING = 4
MSHLFLAGS_RESERVED1 = 8
MSHLFLAGS_RESERVED2 = 16
MSHLFLAGS_RESERVED3 = 32
MSHLFLAGS_RESERVED4 = 64

class tagMSHLFLAGS(enum.IntFlag):
    MSHLFLAGS_NORMAL = 0
    MSHLFLAGS_TABLESTRONG = 1
    MSHLFLAGS_TABLEWEAK = 2
    MSHLFLAGS_NOPING = 4
    MSHLFLAGS_RESERVED1 = 8
    MSHLFLAGS_RESERVED2 = 16
    MSHLFLAGS_RESERVED3 = 32
    MSHLFLAGS_RESERVED4 = 64

MSHLFLAGS = tagMSHLFLAGS

MSHCTX_LOCAL = 0
MSHCTX_NOSHAREDMEM = 1
MSHCTX_DIFFERENTMACHINE = 2
MSHCTX_INPROC = 3
MSHCTX_CROSSCTX = 4

class tagMSHCTX(enum.IntFlag):
    MSHCTX_LOCAL = 0
    MSHCTX_NOSHAREDMEM = 1
    MSHCTX_DIFFERENTMACHINE = 2
    MSHCTX_INPROC = 3
    MSHCTX_CROSSCTX = 4

MSHCTX = tagMSHCTX

class _BYTE_BLOB(Structure):
    _fields_ = [('clSize', ULONG),
                ('abData', BYTE * 1)
    ]

BYTE_BLOB = _BYTE_BLOB
UP_BYTE_BLOB = POINTER(BYTE_BLOB)

class _WORD_BLOB(Structure):
    _fields_ = [('clSize', ULONG),
                ('asData', USHORT * 1)
    ]

WORD_BLOB = _WORD_BLOB
UP_WORD_BLOB = POINTER(WORD_BLOB)

class _DWORD_BLOB(Structure):
    _fields_ = [('clSize', ULONG),
                ('alData', ULONG * 1)
    ]

DWORD_BLOB = _DWORD_BLOB
UP_DWORD_BLOB = POINTER(DWORD_BLOB)

class _FLAGGED_BYTE_BLOB(Structure):
    _fields_ = [('fFlags', ULONG),
                ('clSize', ULONG),
                ('abData', BYTE * 1)
    ]

FLAGGED_BYTE_BLOB = _FLAGGED_BYTE_BLOB
UP_FLAGGED_BYTE_BLOB = POINTER(FLAGGED_BYTE_BLOB)

class _FLAGGED_WORD_BLOB(Structure):
    _fields_ = [('fFlags', ULONG),
                ('clSize', ULONG),
                ('asData', USHORT * 1)
    ]

FLAGGED_WORD_BLOB = _FLAGGED_WORD_BLOB
UP_FLAGGED_WORD_BLOB = POINTER(FLAGGED_WORD_BLOB)

class _BYTE_SIZEDARR(Structure):
    _fields_ = [('clSize', ULONG),
                ('pData', PBYTE)
    ]

BYTE_SIZEDARR = _BYTE_SIZEDARR

class _SHORT_SIZEDARR(Structure):
    _fields_ = [('clSize', ULONG),
                ('pData', PUSHORT)
    ]

WORD_SIZEDARR = _SHORT_SIZEDARR

class _LONG_SIZEDARR(Structure):
    _fields_ = [('clSize', ULONG),
                ('pData', PULONG)
    ]

DWORD_SIZEDARR = _LONG_SIZEDARR

class _HYPER_SIZEDARR(Structure):
    _fields_ = [('clSize', ULONG),
                ('pData', POINTER(hyper))
    ]

HYPER_SIZEDARR = _HYPER_SIZEDARR

boolean = BOOLEAN

class tagBLOB(Structure):
    _fields_ = [('cbSize', ULONG),
                ('pBlobData', PBYTE)
    ]

BLOB = tagBLOB
LPBLOB = POINTER(BLOB)

class _SID_IDENTIFIER_AUTHORITY(Structure):
    _fields_ = [('Value', UCHAR * 6)]

SID_IDENTIFIER_AUTHORITY = _SID_IDENTIFIER_AUTHORITY
PSID_IDENTIFIER_AUTHORITY = POINTER(SID_IDENTIFIER_AUTHORITY)

class _SID(Structure):
    _fields_ = [('Revision', BYTE),
                ('SubAuthorityCount', BYTE),
                ('IdentifierAuthority', SID_IDENTIFIER_AUTHORITY),
                ('SubAuthority', DWORD * 1)
    ]

SID = _SID
PISID = POINTER(SID)

class _SID_AND_ATTRIBUTES(Structure):
    _fields_ = [('Sid', PSID),
                ('Attributes', DWORD)
    ]

SID_AND_ATTRIBUTES = _SID_AND_ATTRIBUTES
PSID_AND_ATTRIBUTES = POINTER(SID_AND_ATTRIBUTES)
