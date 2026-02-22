# coding = 'utf-8'

import sys
import enum
import platform
from method.System.sdkddkver import *
from method.System.winusutypes import *
from method.System.guiddef import GUID, DEFINE_GUID
from method.System.errcheck import win32_to_errcheck
from method.System.public_dll import kernel32, ntdll
from method.System.win32typing import CDataType as _CDataType
from method.System.wchar import memcpy, memcmp, memset, memmove


class _OBJECT_ATTRIBUTES(Structure):
    _fields_ = [('Length', ULONG),
                ('RootDirectory', HANDLE),
                ('ObjectName', PUNICODE_STRING),
                ('Attributes', ULONG),
                ('SecurityDescriptor', PVOID),
                ('SecurityQualityOfService', PVOID)
    ]


class _CLIENT_ID(Structure):
    _fields_ = [('UniqueProcess', HANDLE),
                ('UniqueThread', HANDLE)
    ]


ACCESS_MASK = ULONG
OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES
POBJECT_ATTRIBUTES = ctypes.POINTER(OBJECT_ATTRIBUTES)
PCOBJECT_ATTRIBUTES = POBJECT_ATTRIBUTES
CLIENT_ID = _CLIENT_ID
PCLIENT_ID = ctypes.POINTER(CLIENT_ID)


def offsetof(Type: Structure | Union, Field: str) -> int:       # from stddef.h
    return getattr(Type, Field).offset


##############################################################
# winnt.h

def TYPE_ALIGNMENT(t: _CDataType) -> int:
    class _ChTeTemp(Structure):
        _fields_ = [('x', CHAR),
                    ('test', t)
        ]
    return offsetof(_ChTeTemp, 'test')


def PROBE_ALIGNMENT(_s: _CDataType) -> int:
    if platform.machine().lower() in ['amd64', 'i386']:
        return TYPE_ALIGNMENT(DWORD)
    elif platform.machine().lower() in ['ia64', 'aarch64', 'arm']:
        return (TYPE_ALIGNMENT (_s) 
                if TYPE_ALIGNMENT (_s) > TYPE_ALIGNMENT (DWORD) else TYPE_ALIGNMENT (DWORD)
        )
    else:
        raise OSError('No supported target architecture.')


if platform.machine().lower() == 'amd64':
    def PROBE_ALIGNMENT32(_s):
        return TYPE_ALIGNMENT(DWORD)


def C_ASSERT(e):
    INT * 1 if e else INT * -1


X86_CACHE_ALIGNMENT_SIZE = 64
ARM_CACHE_ALIGNMENT_SIZE = 128

if platform.machine().lower() in ['amd64', 'i386']:
    SYSTEM_CACHE_ALIGNMENT_SIZE = X86_CACHE_ALIGNMENT_SIZE
elif platform.machine().lower() in ['aarch64', 'arm']:
    SYSTEM_CACHE_ALIGNMENT_SIZE = ARM_CACHE_ALIGNMENT_SIZE
else:
    raise OSError('Must define a target architecture.')

ANYSIZE_ARRAY = 1

if sys.maxsize > 2**32:
    MAX_NATURAL_ALIGNMENT = sizeof(ULONGLONG())
    MEMORY_ALLOCATION_ALIGNMENT = 16
else:
    MAX_NATURAL_ALIGNMENT = sizeof(DWORD())
    MEMORY_ALLOCATION_ALIGNMENT = 8

PRAGMA_DEPRECATED_DDK = 0

PVOID64 = PVOID * 64

NTAPI = WINFUNCTYPE
_LONG32 = LONG

class _M128A(Structure):
    _align_ = 16
    _fields_ = [('Low', ULONGLONG),
                ('High', LONGLONG)
    ]

M128A = _M128A
PM128A = POINTER(M128A)

class _XSAVE_FORMAT(Structure):
    _align_ = 16
    _fields_ = [('ControlWord', WORD),
                ('StatusWord', WORD),
                ('TagWord', BYTE),
                ('Reserved1', BYTE),
                ('ErrorOpcode', WORD),
                ('ErrorOffset', DWORD),
                ('ErrorSelector', WORD),
                ('Reserved2', WORD),
                ('DataOffset', DWORD),
                ('DataSelector', WORD),
                ('Reserved3', WORD),
                ('MxCsr', DWORD),
                ('MxCsr_Mask', DWORD),
                ('FloatRegisters', M128A)
    ]

    if sys.maxsize > 2 ** 32:
        _fields_.append(('XmmRegisters', M128A * 16))
        _fields_.append(('Reserved4', BYTE * 96))
    else:
        _fields_.append(('XmmRegisters', M128A * 8))
        _fields_.append(('Reserved4', BYTE * 220))
        _fields_.append(('Cr0NpxState', DWORD))

XSAVE_FORMAT = _XSAVE_FORMAT
PXSAVE_FORMAT = POINTER(XSAVE_FORMAT)

class _XSAVE_CET_U_FORMAT(Structure):
    _fields_ = [('Ia32CetUMsr', DWORD64),
                ('Ia32Pl3SspMsr', DWORD64)
    ]
    
XSAVE_CET_U_FORMAT = _XSAVE_CET_U_FORMAT
PXSAVE_CET_U_FORMAT = POINTER(XSAVE_CET_U_FORMAT)

class _XSAVE_AREA_HEADER(Structure):
    _align_ = 8
    _fields_ = [('Mask', DWORD64),
                ('Reserved', DWORD64 * 7)
    ]

XSAVE_AREA_HEADER = _XSAVE_AREA_HEADER
PXSAVE_AREA_HEADER = POINTER(XSAVE_AREA_HEADER)

class _XSAVE_AREA(Structure):
    _align_ = 16
    _fields_ = [('LegacyState', XSAVE_FORMAT),
                ('Header', XSAVE_AREA_HEADER)
    ]

XSAVE_AREA = _XSAVE_AREA
PXSAVE_AREA = POINTER(XSAVE_AREA)

class _XSTATE_CONTEXT(Structure):
    _fields_ = [('Mask', DWORD64),
                ('Length', DWORD),
                ('Reserved1', DWORD),
                ('Area', PXSAVE_AREA),
                ('Buffer', PVOID)
    ]

    if platform.machine().lower() == 'i386':
        _fields_.append(('Reserved2', DWORD))
        _fields_.append(('Reserved3', DWORD))

XSTATE_CONTEXT = _XSTATE_CONTEXT
PXSTATE_CONTEXT = POINTER(XSTATE_CONTEXT)

class _KERNEL_CET_CONTEXT(Structure):
    class AllFlagsUn(Union):
        class UsePopShadowUn(LittleEndianUnion):
            _fields_ = [('UseWrss', WORD, 1),
                        ('PopShadowStackOne', WORD, 1),
                        ('Unused', WORD, 14),
            ]
        
        _anonymous_ = ['UsePopShadowUn']
        _fields_ = [('AllFlags', WORD), 
                    ('UsePopShadowUn', UsePopShadowUn)
        ]

    _anonymous_ = ['AllFlagsUn']
    _fields_ = [('Ssp', DWORD64),
                ('Rip', DWORD64),
                ('SegCs', WORD),
                ('AllFlagsUn', AllFlagsUn),
                ('Fill', WORD * 2)
    ]

KERNEL_CET_CONTEXT = _KERNEL_CET_CONTEXT
PKERNEL_CET_CONTEXT = POINTER(KERNEL_CET_CONTEXT)

class _SCOPE_TABLE_AMD64(Structure):
    class ScopeRecord(Structure):
        _fields_ = [('BeginAddress', DWORD),
                    ('EndAddress', DWORD),
                    ('HandlerAddress', DWORD),
                    ('JumpTarget', DWORD)
        ]

    # _anonymous_ = ['ScopeRecord']
    _fields_ = [('Count', DWORD),
                ('ScopeRecord', ScopeRecord * 1)
    ]

SCOPE_TABLE_AMD64 = _SCOPE_TABLE_AMD64
PSCOPE_TABLE_AMD64 = POINTER(SCOPE_TABLE_AMD64)

LPWCH = PWCHAR
PWCH = PWCHAR
LPCWCH = PWCHAR
PCWCH = PWCHAR
NWPSTR = PWCHAR
PZPWSTR = PWSTR
PCZPWSTR = PWSTR
LPUWSTR = PWCHAR
PUWSTR = PWCHAR
PZPCWSTR = PCWSTR
LPCUWSTR = PWCHAR
PCUWSTR = PWCHAR
PZZWSTR = PWCHAR
PCZZWSTR = PWCHAR
PUZZWSTR = PWCHAR
PCUZZWSTR = PWCHAR
PNZWCH = PWCHAR
PCNZWCH = PWCHAR
PUNZWCH = PWCHAR
PCUNZWCH = PWCHAR

LPCWCHAR = PWCHAR
PCWCHAR = PWCHAR
LPCUWCHAR = PWCHAR
PCUWCHAR = PWCHAR

UCSCHAR = ULONG

UCSCHAR_INVALID_CHARACTER = 0xffffffff
MIN_UCSCHAR = 0
MAX_UCSCHAR = 0x0010ffff

PUCSCHAR = POINTER(UCSCHAR)
PCUCSCHAR = PUCSCHAR
PUCSSTR = PCUCSCHAR
PUUCSSTR = PUCSSTR
PCUCSSTR = PUCSCHAR
PCUUCSSTR = PUCSCHAR
PUUCSCHAR = PUCSCHAR
PCUUCSCHAR = PUCSCHAR

LPCH = PCHAR
PCH = PCHAR
LPCCH = PCHAR
PCCH = PCHAR
NPSTR = PCHAR
LPSTR = PCHAR
PZPSTR = PSTR
PCZPSTR = PSTR
PZPCSTR = PCSTR
PZZSTR = PCHAR
PCZZSTR = PCHAR
PNZCH = PCHAR
PCNZCH = PCHAR

LPTCH = LPWSTR
PTCH = LPWSTR
PUTSTR = LPUWSTR
LPUTSTR = LPUWSTR
PCUTSTR = LPCUWSTR
LPCUTSTR = LPCUWSTR
LP = LPWSTR
PZZTSTR = PZZWSTR
PCZZTSTR = PCZZWSTR
PUZZTWSTR = PCZZWSTR
PZPTSTR = PZPWSTR
PNZTCH = PNZWCH
PCNZTCH = PCNZWCH
PCUNZTCH = PCNZWCH

KAFFINITY = ULONG_PTR   # from basetsd.h

class _GROUP_AFFINITY(Structure):
    _fields_ = [('Mask', KAFFINITY),
                ('Group', WORD),
                ('Reserved', WORD * 3)
    ]

GROUP_AFFINITY = _GROUP_AFFINITY
PGROUP_AFFINITY = POINTER(GROUP_AFFINITY)


def DECLARE_HANDLE(name):
    return HANDLE(name).value


FCHAR = BYTE
FSHORT = WORD
FLONG = DWORD

UNSPECIFIED_COMPARTMENT_ID = 0
DEFAULT_COMPARTMENT_ID = 1

class COMPARTMENT_ID(enum.IntFlag):
    UNSPECIFIED_COMPARTMENT_ID = 0
    DEFAULT_COMPARTMENT_ID = 1

PCOMPARTMENT_ID = COMPARTMENT_ID

APPLICATION_ERROR_MASK = 0x20000000
ERROR_SEVERITY_SUCCESS = 0x00000000
ERROR_SEVERITY_INFORMATIONAL = 0x40000000
ERROR_SEVERITY_WARNING = 0x80000000
ERROR_SEVERITY_ERROR = 0xC0000000


class _FLOAT128(Structure):
    _fields_ = [('LowPart', INT64), 
                ('HighPart', INT64)
    ]


FLOAT128 = _FLOAT128
PFLOAT128 = ctypes.POINTER(FLOAT128)

MAXLONGLONG = 0x7fffffffffffffff

class _LARGE_INTEGER(Union):
    class DUMMYSTRUCTNAME(Structure):
        _fields_ = [('LowPart', DWORD),
                    ('HighPart', LONG)
        ]

    class u(Structure):
        _fields_ = [('LowPart', DWORD),
                    ('HighPart', LONG)
        ]

    _anonymous_ = ['DUMMYSTRUCTNAME', 'u']
    _fields_ = [('QuadPart', LONGLONG),
                ('DUMMYSTRUCTNAME', DUMMYSTRUCTNAME),
                ('u', u)
    ] 

LARGE_INTEGER = _LARGE_INTEGER
PLARGE_INTEGER = POINTER(LARGE_INTEGER)

class _ULARGE_INTEGER(Union):
    class DUMMYSTRUCTNAME(Structure):
        _fields_ = [('LowPart', DWORD),
                    ('HighPart', DWORD)
        ]

    class u(Structure):
        _fields_ = [('LowPart', DWORD),
                    ('HighPart', DWORD)
        ]

    _anonymous_ = ['DUMMYSTRUCTNAME', 'u']
    _fields_ = [('QuadPart', ULONGLONG),
                ('DUMMYSTRUCTNAME', DUMMYSTRUCTNAME),
                ('u', u)
    ] 

ULARGE_INTEGER = _ULARGE_INTEGER
PULARGE_INTEGER = POINTER(ULARGE_INTEGER)

RTL_REFERENCE_COUNT = LONG_PTR
PRTL_REFERENCE_COUNT = POINTER(RTL_REFERENCE_COUNT)

RTL_REFERENCE_COUNT32 = LONG
PRTL_REFERENCE_COUNT32 = POINTER(RTL_REFERENCE_COUNT32)

class _LUID(Structure):
    _fields_ = [('LowPart', DWORD), 
                ('HighPart', LONG)
    ]

LUID = _LUID
PLUID = POINTER(LUID)

def Int32x32To64(a: int | float, b: int | float) -> int:
    a = LONGLONG(LONG(a).value).value
    b = LONGLONG(LONG(a).value).value
    return int(a) * int(b)

def UInt32x32To64(a: int | float, b: int | float) -> int:
    a = ULONGLONG(UINT(a).value).value
    b = ULONGLONG(UINT(b).value).value
    return int(a) * int(b)

def Int64ShllMod32(a: int, b: int) -> int:
    return ULONGLONG(a).value << b

def Int64ShraMod32(a: int, b: int) -> int:
    return LONGLONG(a).value >> b

def Int64ShrlMod32(a: int, b: int) -> int:
    return ULONGLONG(a).value << b

def _rotl8(Value: int, Shift: int) -> int:
    return (Value << Shift) | (Value >> (8 - Shift))

def _rotl16(Value: int, Shift: int) -> int:
    return (Value << Shift) | (Value >> (16 - Shift))

def _rotr8(Value: int, Shift: int) -> int:
    return (Value >> Shift) | (Value << (8 - Shift))

def _rotr16(Value: int, Shift: int) -> int:
    return (Value >> Shift) | (Value << (16 - Shift))

RotateLeft8 = _rotl8
RotateLeft16 = _rotl16
RotateRight8 = _rotr8
RotateRight16 = _rotr16

def _rotl(Value: int, Shift: int) -> int:
    return (Value << Shift) | (Value >> (32 - Shift))

def _rotr(Value: int, Shift: int) -> int:
    return (Value >> Shift) | (Value << (32 - Shift))

def _rotl64(Value: int, Shift: int) -> int:
    return (Value << Shift) | (Value >> (64 - Shift))

def _rotr64(Value: int, Shift: int) -> int:
    return (Value >> Shift) | (Value << (64 - Shift))

RotateLeft32 = _rotl
RotateLeft64 = _rotl64
RotateRight32 = _rotr
RotateRight64 = _rotr64

ANSI_NULL = 0
UNICODE_NULL = 0
UNICODE_STRING_MAX_BYTES = WORD(65534).value
UNICODE_STRING_MAX_CHARS = 32767

BOOLEAN = BYTE
PBOOLEAN = POINTER(BOOLEAN)

class _LIST_ENTRY(Structure):
   pass

_LIST_ENTRY._fields_ = [('Flink', POINTER(_LIST_ENTRY)),
                        ('Blink', POINTER(_LIST_ENTRY))
]

LIST_ENTRY = _LIST_ENTRY
PLIST_ENTRY = POINTER(LIST_ENTRY)
PRLIST_ENTRY = POINTER(LIST_ENTRY)

class _SINGLE_LIST_ENTRY(Structure):
    pass

_SINGLE_LIST_ENTRY._fields_ = [('Next', POINTER(_SINGLE_LIST_ENTRY))]

SINGLE_LIST_ENTRY = _SINGLE_LIST_ENTRY
PSINGLE_LIST_ENTRY = POINTER(_SINGLE_LIST_ENTRY)

class LIST_ENTRY32(Structure):
    pass

LIST_ENTRY32._fields_ = [('Flink', DWORD),
                         ('Blink', DWORD)
]

PLIST_ENTRY32 = POINTER(LIST_ENTRY32)

class LIST_ENTRY64(Structure):
    pass

LIST_ENTRY64._fields_ = [('Flink', ULONGLONG),
                         ('Blink', ULONGLONG)
]

PLIST_ENTRY64 = POINTER(LIST_ENTRY64)

class _OBJECTID(Structure):
    _fields_ = [('Lineage', GUID),
                ('Uniquifier', DWORD)
    ]

OBJECTID = _OBJECTID

MINCHAR = 0x80
MAXCHAR = 0x7f
MINSHORT = 0x8000
MAXSHORT = 0x7fff
MINLONG = 0x80000000
MAXLONG = 0x7fffffff
MAXBYTE = 0xff
MAXWORD = 0xffff
MAXDWORD = 0xffffffff


def FIELD_OFFSET(Type: _CDataType, Field: str) -> int:
    return LONG(offsetof(Type, Field)).value


def RTL_FIELD_SIZE(_type: _CDataType, field: str) -> int:
    for name, field_type in type._fields_:
        if field == name:
            return sizeof(field_type)
    raise AttributeError(f"type object '{_type}' has no attribute '{field}'")


def RTL_SIZEOF_THROUGH_FIELD(type: _CDataType, field: str) -> int:
    return FIELD_OFFSET(type, field) + RTL_FIELD_SIZE(type, field)


def RTL_CONTAINS_FIELD(Struct: _CDataType, Size: int, Field: str) -> bool:
    for name, field_type in Struct._fields_:
        if Field == name:
            return (offsetof(Struct, Field) + sizeof(field_type)) <= Size
    raise AttributeError(f"type object '{Struct}' has no attribute '{Field}'")


def RTL_PADDING_BETWEEN_FIELDS(T: _CDataType, F1: str, F2: str) -> int:
    return ((FIELD_OFFSET(T,F2) - FIELD_OFFSET(T,F1) - RTL_FIELD_SIZE(T,F1)) 
            if FIELD_OFFSET(T,F2) > FIELD_OFFSET(T,F1) else (FIELD_OFFSET(T,F1) - FIELD_OFFSET(T,F2) - RTL_FIELD_SIZE(T,F2))
    )


def RTL_NUMBER_OF_V1(A: Array) -> int:
    return A._length_


RTL_NUMBER_OF_V2 = RTL_NUMBER_OF_V1


def RTL_NUMBER_OF(A: Array) -> int:
    return RTL_NUMBER_OF_V1(A)


def ARRAYSIZE(A: Array) -> int:
    return RTL_NUMBER_OF_V2(A)


def _ARRAYSIZE(A: Array) -> int:
    return RTL_NUMBER_OF_V1(A)


def RTL_FIELD_TYPE(type: _CDataType, field: str) -> int:
    return offsetof(type, field)


def RTL_NUMBER_OF_FIELD(type: _CDataType, field: str) -> int:
    return RTL_NUMBER_OF(RTL_FIELD_TYPE(type, field))


def COMPILETIME_OR_2FLAGS(a: int, b: int) -> int:
    return (UINT(a).value | UINT(b).value)


def COMPILETIME_OR_3FLAGS(a: int, b: int, c: int) -> int:
    return (UINT(a).value | UINT(b).value | UINT(c).value)


def COMPILETIME_OR_4FLAGS(a: int, b: int, c: int, d: int) -> int:
    return (UINT(a).value | UINT(b).value | UINT(c).value | UINT(d).value)


def COMPILETIME_OR_5FLAGS(a: int, b: int, c: int, d: int, e: int) -> int:
    return (UINT(a).value | UINT(b).value | UINT(c).value | UINT(d).value | UINT(e).value)


def RTL_BITS_OF(sizeOfArg):
    return sizeof(sizeOfArg) * 8


def RTL_BITS_OF_FIELD(type: _CDataType, field: str) -> int:
    return RTL_BITS_OF(RTL_FIELD_TYPE(type, field))


def CONTAINING_RECORD(address: int, type: _CDataType, field: str) -> None:
    setattr(type, field, (PCHAR(address).value - ULONG_PTR(offsetof(type, field)).value))


EXCEPTION_MAXIMUM_PARAMETERS = 15

class _EXCEPTION_RECORD(Structure):
    pass

_EXCEPTION_RECORD._fields_ = [('ExceptionCode', DWORD),
                              ('ExceptionFlags', DWORD),
                              ('ExceptionRecord', POINTER(_EXCEPTION_RECORD)),
                              ('ExceptionAddress', PVOID),
                              ('NumberParameters', DWORD),
                              ('ExceptionInformation', ULONG_PTR * EXCEPTION_MAXIMUM_PARAMETERS)
]

EXCEPTION_RECORD = _EXCEPTION_RECORD
PEXCEPTION_RECORD = POINTER(EXCEPTION_RECORD)

class _EXCEPTION_RECORD32(Structure):
    _fields_ = [('ExceptionCode', DWORD),
                ('ExceptionFlags', DWORD),
                ('ExceptionRecord', DWORD),
                ('ExceptionAddress', DWORD),
                ('NumberParameters', DWORD),
                ('ExceptionInformation', DWORD * EXCEPTION_MAXIMUM_PARAMETERS)
    ]

EXCEPTION_RECORD32 = _EXCEPTION_RECORD32
PEXCEPTION_RECORD32 = POINTER(EXCEPTION_RECORD32)

class _EXCEPTION_RECORD64(Structure):
    _fields_ = [('ExceptionCode', DWORD),
                ('ExceptionFlags', DWORD),
                ('ExceptionRecord', DWORD64),
                ('ExceptionAddress', DWORD64),
                ('NumberParameters', DWORD),
                ('ExceptionInformation', DWORD64 * EXCEPTION_MAXIMUM_PARAMETERS)
    ]

EXCEPTION_RECORD64 = _EXCEPTION_RECORD64
PEXCEPTION_RECORD64 = POINTER(EXCEPTION_RECORD64)

class _XMM_SAVE_AREA32(Structure):
    _fields_ = [('ControlWord', WORD),
                ('StatusWord', WORD),
                ('TagWord', BYTE),
                ('Reserved1', BYTE),
                ('ErrorOpcode', WORD),
                ('ErrorOffset', DWORD),
                ('ErrorSelector', WORD),
                ('Reserved2', WORD),
                ('DataOffset', DWORD),
                ('DataSelector', WORD),
                ('Reserved3', WORD),
                ('MxCsr', DWORD),
                ('MxCsr_Mask', DWORD),
                ('FloatRegisters', M128A * 8),
                ('XmmRegisters', M128A * 16),
                ('Reserved4', BYTE * 96)
    ]

XMM_SAVE_AREA32 = _XMM_SAVE_AREA32
PXMM_SAVE_AREA32 = POINTER(XMM_SAVE_AREA32)

LEGACY_SAVE_AREA_LENGTH = sizeof(PXMM_SAVE_AREA32())

class _CONTEXT(Structure):
    class FSave(Union):
        class Xmm(Structure):
            _fields_ = [('Header', M128A * 2),
                        ('Legacy', M128A * 8),
                        ('Xmm0', M128A),
                        ('Xmm1', M128A),
                        ('Xmm2', M128A),
                        ('Xmm3', M128A),
                        ('Xmm4', M128A),
                        ('Xmm5', M128A),
                        ('Xmm6', M128A),
                        ('Xmm7', M128A),
                        ('Xmm8', M128A),
                        ('Xmm9', M128A),
                        ('Xmm10', M128A),
                        ('Xmm11', M128A),
                        ('Xmm12', M128A),
                        ('Xmm13', M128A),
                        ('Xmm14', M128A),
                        ('Xmm15', M128A)
            ]
        
        _anonymous_ = ['Xmm']
        _fields_ = [('FltSave', XMM_SAVE_AREA32),
                    ('FloatSave', XMM_SAVE_AREA32),
                    ('Xmm', Xmm)
        ]

    _align_ = 16
    _anonymous_ = ['FSave']
    _fields_ = [('P1Home', DWORD64),
                ('P2Home', DWORD64),
                ('P3Home', DWORD64),
                ('P4Home', DWORD64),
                ('P5Home', DWORD64),
                ('P6Home', DWORD64),
                ('ContextFlags', DWORD),
                ('MxCsr', DWORD),
                ('SegCs', WORD),
                ('SegDs', WORD),
                ('SegEs', WORD),
                ('SegFs', WORD),
                ('SegGs', WORD),
                ('SegSs', WORD),
                ('EFlags', DWORD),
                ('Dr0', DWORD64),
                ('Dr1', DWORD64),
                ('Dr2', DWORD64),
                ('Dr3', DWORD64),
                ('Dr6', DWORD64),
                ('Dr7', DWORD64),
                ('Rax', DWORD64),
                ('Rcx', DWORD64),
                ('Rdx', DWORD64),
                ('Rbx', DWORD64),
                ('Rsp', DWORD64),
                ('Rbp', DWORD64),
                ('Rsi', DWORD64),
                ('Rdi', DWORD64),
                ('R8', DWORD64),
                ('R9', DWORD64),
                ('R10', DWORD64),
                ('R11', DWORD64),
                ('R12', DWORD64),
                ('R13', DWORD64),
                ('R14', DWORD64),
                ('R15', DWORD64),
                ('Rip', DWORD64),
                ('FSave', FSave),
                ('VectorRegister', M128A),
                ('VectorControl', DWORD64),
                ('DebugControl', DWORD64),
                ('LastBranchToRip', DWORD64),
                ('LastBranchFromRip', DWORD64),
                ('LastExceptionToRip', DWORD64),
                ('LastExceptionFromRip', DWORD64)
    ]

CONTEXT = _CONTEXT
PCONTEXT = POINTER(CONTEXT)
LPCONTEXT = PCONTEXT

RUNTIME_FUNCTION_INDIRECT = 0x1

class _RUNTIME_FUNCTION(Structure):
    _fields_ = [('BeginAddress', DWORD),
                ('EndAddress', DWORD),
                ('UnwindData', DWORD)
    ]

RUNTIME_FUNCTION = _RUNTIME_FUNCTION
PRUNTIME_FUNCTION = POINTER(RUNTIME_FUNCTION)

PGET_RUNTIME_FUNCTION_CALLBACK = CALLBACK(PRUNTIME_FUNCTION, DWORD64, PVOID)
POUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK = CALLBACK(DWORD, HANDLE, PVOID, PDWORD, POINTER(PRUNTIME_FUNCTION))

class _EXCEPTION_POINTERS(Structure):
    _fields_ = [('ExceptionRecord', PEXCEPTION_RECORD),
                ('ContextRecord', PCONTEXT)
    ]

EXCEPTION_POINTERS = _EXCEPTION_POINTERS
PEXCEPTION_POINTERS = POINTER(EXCEPTION_POINTERS)

ENCLAVE_SHORT_ID_LENGTH             = 16
ENCLAVE_LONG_ID_LENGTH              = 32

VER_WORKSTATION_NT                  = 0x40000000
VER_SERVER_NT                       = 0x80000000
VER_SUITE_SMALLBUSINESS             = 0x00000001
VER_SUITE_ENTERPRISE                = 0x00000002
VER_SUITE_BACKOFFICE                = 0x00000004
VER_SUITE_COMMUNICATIONS            = 0x00000008
VER_SUITE_TERMINAL                  = 0x00000010
VER_SUITE_SMALLBUSINESS_RESTRICTED  = 0x00000020
VER_SUITE_EMBEDDEDNT                = 0x00000040
VER_SUITE_DATACENTER                = 0x00000080
VER_SUITE_SINGLEUSERTS              = 0x00000100
VER_SUITE_PERSONAL                  = 0x00000200
VER_SUITE_BLADE                     = 0x00000400
VER_SUITE_EMBEDDED_RESTRICTED       = 0x00000800
VER_SUITE_SECURITY_APPLIANCE        = 0x00001000
VER_SUITE_STORAGE_SERVER            = 0x00002000
VER_SUITE_COMPUTE_SERVER            = 0x00004000
VER_SUITE_WH_SERVER                 = 0x00008000
VER_SUITE_MULTIUSERTS               = 0x00020000

PRODUCT_UNDEFINED                         = 0x0

PRODUCT_ULTIMATE                          = 0x1
PRODUCT_HOME_BASIC                        = 0x2
PRODUCT_HOME_PREMIUM                      = 0x3
PRODUCT_ENTERPRISE                        = 0x4
PRODUCT_HOME_BASIC_N                      = 0x5
PRODUCT_BUSINESS                          = 0x6
PRODUCT_STANDARD_SERVER                   = 0x7
PRODUCT_DATACENTER_SERVER                 = 0x8
PRODUCT_SMALLBUSINESS_SERVER              = 0x9
PRODUCT_ENTERPRISE_SERVER                 = 0xa
PRODUCT_STARTER                           = 0xb
PRODUCT_DATACENTER_SERVER_CORE            = 0xc
PRODUCT_STANDARD_SERVER_CORE              = 0xd
PRODUCT_ENTERPRISE_SERVER_CORE            = 0xe
PRODUCT_ENTERPRISE_SERVER_IA64            = 0xf
PRODUCT_BUSINESS_N                        = 0x10
PRODUCT_WEB_SERVER                        = 0x11
PRODUCT_CLUSTER_SERVER                    = 0x12
PRODUCT_HOME_SERVER                       = 0x13
PRODUCT_STORAGE_EXPRESS_SERVER            = 0x14
PRODUCT_STORAGE_STANDARD_SERVER           = 0x15
PRODUCT_STORAGE_WORKGROUP_SERVER          = 0x16
PRODUCT_STORAGE_ENTERPRISE_SERVER         = 0x17
PRODUCT_SERVER_FOR_SMALLBUSINESS          = 0x18
PRODUCT_SMALLBUSINESS_SERVER_PREMIUM      = 0x19
PRODUCT_HOME_PREMIUM_N                    = 0x1a
PRODUCT_ENTERPRISE_N                      = 0x1b
PRODUCT_ULTIMATE_N                        = 0x1c
PRODUCT_WEB_SERVER_CORE                   = 0x1d
PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT  = 0x1e
PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY    = 0x1f
PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING   = 0x20
PRODUCT_SERVER_FOUNDATION                 = 0x21
PRODUCT_HOME_PREMIUM_SERVER               = 0x22
PRODUCT_SERVER_FOR_SMALLBUSINESS_V        = 0x23
PRODUCT_STANDARD_SERVER_V                 = 0x24
PRODUCT_DATACENTER_SERVER_V               = 0x25
PRODUCT_SERVER_V                          = 0x25
PRODUCT_ENTERPRISE_SERVER_V               = 0x26
PRODUCT_DATACENTER_SERVER_CORE_V          = 0x27
PRODUCT_STANDARD_SERVER_CORE_V            = 0x28
PRODUCT_ENTERPRISE_SERVER_CORE_V          = 0x29
PRODUCT_HYPERV                            = 0x2a
PRODUCT_STORAGE_EXPRESS_SERVER_CORE       = 0x2b
PRODUCT_STORAGE_STANDARD_SERVER_CORE      = 0x2c
PRODUCT_STORAGE_WORKGROUP_SERVER_CORE     = 0x2d
PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE    = 0x2e
PRODUCT_STARTER_N                         = 0x2f
PRODUCT_PROFESSIONAL                      = 0x30
PRODUCT_PROFESSIONAL_N                    = 0x31
PRODUCT_SB_SOLUTION_SERVER                = 0x32
PRODUCT_SERVER_FOR_SB_SOLUTIONS           = 0x33
PRODUCT_STANDARD_SERVER_SOLUTIONS         = 0x34
PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE    = 0x35
PRODUCT_SB_SOLUTION_SERVER_EM             = 0x36
PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM        = 0x37
PRODUCT_SOLUTION_EMBEDDEDSERVER           = 0x38
PRODUCT_SOLUTION_EMBEDDEDSERVER_CORE      = 0x39
PRODUCT_PROFESSIONAL_EMBEDDED             = 0x3A
PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT     = 0x3B
PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL     = 0x3C
PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC  = 0x3D
PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC  = 0x3E
PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE = 0x3f
PRODUCT_CLUSTER_SERVER_V                  = 0x40
PRODUCT_EMBEDDED                          = 0x41
PRODUCT_STARTER_E                         = 0x42
PRODUCT_HOME_BASIC_E                      = 0x43
PRODUCT_HOME_PREMIUM_E                    = 0x44
PRODUCT_PROFESSIONAL_E                    = 0x45
PRODUCT_ENTERPRISE_E                      = 0x46
PRODUCT_ULTIMATE_E                        = 0x47
PRODUCT_ENTERPRISE_EVALUATION             = 0x48
PRODUCT_MULTIPOINT_STANDARD_SERVER        = 0x4C
PRODUCT_MULTIPOINT_PREMIUM_SERVER         = 0x4D
PRODUCT_STANDARD_EVALUATION_SERVER        = 0x4F
PRODUCT_DATACENTER_EVALUATION_SERVER      = 0x50
PRODUCT_ENTERPRISE_N_EVALUATION           = 0x54
PRODUCT_EMBEDDED_AUTOMOTIVE               = 0x55
PRODUCT_EMBEDDED_INDUSTRY_A               = 0x56
PRODUCT_THINPC                            = 0x57
PRODUCT_EMBEDDED_A                        = 0x58
PRODUCT_EMBEDDED_INDUSTRY                 = 0x59
PRODUCT_EMBEDDED_E                        = 0x5A
PRODUCT_EMBEDDED_INDUSTRY_E               = 0x5B
PRODUCT_EMBEDDED_INDUSTRY_A_E             = 0x5C
PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER = 0x5F
PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER  = 0x60
PRODUCT_CORE_ARM                          = 0x61
PRODUCT_CORE_N                            = 0x62
PRODUCT_CORE_COUNTRYSPECIFIC              = 0x63
PRODUCT_CORE_SINGLELANGUAGE               = 0x64
PRODUCT_CORE_LANGUAGESPECIFIC             = 0x64
PRODUCT_CORE                              = 0x65
PRODUCT_PROFESSIONAL_WMC                  = 0x67
PRODUCT_MOBILE_CORE                       = 0x68
PRODUCT_EMBEDDED_INDUSTRY_EVAL            = 0x69
PRODUCT_EMBEDDED_INDUSTRY_E_EVAL          = 0x6A
PRODUCT_EMBEDDED_EVAL                     = 0x6B
PRODUCT_EMBEDDED_E_EVAL                   = 0x6C
PRODUCT_NANO_SERVER                       = 0x6D
PRODUCT_CLOUD_STORAGE_SERVER              = 0x6E
PRODUCT_CORE_CONNECTED                    = 0x6F
PRODUCT_PROFESSIONAL_STUDENT              = 0x70
PRODUCT_CORE_CONNECTED_N                  = 0x71
PRODUCT_PROFESSIONAL_STUDENT_N            = 0x72
PRODUCT_CORE_CONNECTED_SINGLELANGUAGE     = 0x73
PRODUCT_CORE_CONNECTED_COUNTRYSPECIFIC    = 0x74
PRODUCT_CONNECTED_CAR                     = 0x75
PRODUCT_INDUSTRY_HANDHELD                 = 0x76
PRODUCT_PPI_PRO                           = 0x77
PRODUCT_ARM64_SERVER                      = 0x78
PRODUCT_EDUCATION                         = 0x79
PRODUCT_EDUCATION_N                       = 0x7a
PRODUCT_IOTUAP                            = 0x7B
PRODUCT_CLOUD_HOST_INFRASTRUCTURE_SERVER  = 0x7C
PRODUCT_ENTERPRISE_S                      = 0x7D
PRODUCT_ENTERPRISE_S_N                    = 0x7E
PRODUCT_PROFESSIONAL_S                    = 0x7F
PRODUCT_PROFESSIONAL_S_N                  = 0x80
PRODUCT_ENTERPRISE_S_EVALUATION           = 0x81
PRODUCT_ENTERPRISE_S_N_EVALUATION         = 0x82
PRODUCT_MOBILE_ENTERPRISE                 = 0x85
PRODUCT_HOLOGRAPHIC                       = 0x87
PRODUCT_HOLOGRAPHIC_BUSINESS              = 0x88
PRODUCT_PRO_SINGLE_LANGUAGE               = 0x8A
PRODUCT_PRO_CHINA                         = 0x8B
PRODUCT_ENTERPRISE_SUBSCRIPTION           = 0x8C
PRODUCT_ENTERPRISE_SUBSCRIPTION_N         = 0x8D
PRODUCT_DATACENTER_NANO_SERVER            = 0x8F
PRODUCT_STANDARD_NANO_SERVER              = 0x90
PRODUCT_DATACENTER_A_SERVER_CORE          = 0x91
PRODUCT_STANDARD_A_SERVER_CORE            = 0x92
PRODUCT_DATACENTER_WS_SERVER_CORE         = 0x93
PRODUCT_STANDARD_WS_SERVER_CORE           = 0x94
PRODUCT_UTILITY_VM                        = 0x95
PRODUCT_DATACENTER_EVALUATION_SERVER_CORE = 0x9F
PRODUCT_STANDARD_EVALUATION_SERVER_CORE   = 0xA0
PRODUCT_PRO_WORKSTATION                   = 0xA1
PRODUCT_PRO_WORKSTATION_N                 = 0xA2
PRODUCT_PRO_FOR_EDUCATION                 = 0xA4
PRODUCT_PRO_FOR_EDUCATION_N               = 0xA5
PRODUCT_AZURE_SERVER_CORE                 = 0xA8
PRODUCT_AZURE_NANO_SERVER                 = 0xA9
PRODUCT_ENTERPRISEG                       = 0xAB
PRODUCT_ENTERPRISEGN                      = 0xAC
PRODUCT_SERVERRDSH                        = 0xAF
PRODUCT_CLOUD                             = 0xB2
PRODUCT_CLOUDN                            = 0xB3
PRODUCT_HUBOS                             = 0xB4
PRODUCT_ONECOREUPDATEOS                   = 0xB6
PRODUCT_CLOUDE                            = 0xB7
PRODUCT_IOTOS                             = 0xB9
PRODUCT_CLOUDEN                           = 0xBA
PRODUCT_IOTEDGEOS                         = 0xBB
PRODUCT_IOTENTERPRISE                     = 0xBC
PRODUCT_LITE                              = 0xBD
PRODUCT_IOTENTERPRISES                    = 0xBF
PRODUCT_XBOX_SYSTEMOS                     = 0xC0
PRODUCT_XBOX_NATIVEOS                     = 0xC1
PRODUCT_XBOX_GAMEOS                       = 0xC2
PRODUCT_XBOX_ERAOS                        = 0xC3
PRODUCT_XBOX_DURANGOHOSTOS                = 0xC4
PRODUCT_XBOX_SCARLETTHOSTOS               = 0xC5
PRODUCT_XBOX_KEYSTONE                     = 0xC6
PRODUCT_AZURE_SERVER_CLOUDHOST            = 0xC7
PRODUCT_AZURE_SERVER_CLOUDMOS             = 0xC8
PRODUCT_CLOUDEDITIONN                     = 0xCA
PRODUCT_CLOUDEDITION                      = 0xCB
PRODUCT_AZURESTACKHCI_SERVER_CORE         = 0x196
PRODUCT_DATACENTER_SERVER_AZURE_EDITION   = 0x197
PRODUCT_DATACENTER_SERVER_CORE_AZURE_EDITION = 0x198

PRODUCT_UNLICENSED                        = 0xabcdabcd

LANG_NEUTRAL                              = 0x00
LANG_INVARIANT                            = 0x7f

LANG_AFRIKAANS                            = 0x36
LANG_ALBANIAN                             = 0x1c
LANG_ALSATIAN                             = 0x84
LANG_AMHARIC                              = 0x5e
LANG_ARABIC                               = 0x01
LANG_ARMENIAN                             = 0x2b
LANG_ASSAMESE                             = 0x4d
LANG_AZERI                                = 0x2c
LANG_AZERBAIJANI			  = 0x2c
LANG_BANGLA				  = 0x45
LANG_BASHKIR                              = 0x6d
LANG_BASQUE                               = 0x2d
LANG_BELARUSIAN                           = 0x23
LANG_BENGALI                              = 0x45
LANG_BRETON                               = 0x7e
LANG_BOSNIAN                              = 0x1a
LANG_BOSNIAN_NEUTRAL                    = 0x781a
LANG_BULGARIAN                            = 0x02
LANG_CATALAN                              = 0x03
LANG_CENTRAL_KURDISH			  = 0x92
LANG_CHEROKEE				  = 0x5c
LANG_CHINESE                              = 0x04
LANG_CHINESE_SIMPLIFIED                   = 0x04
LANG_CHINESE_TRADITIONAL                = 0x7c04
LANG_CORSICAN                             = 0x83
LANG_CROATIAN                             = 0x1a
LANG_CZECH                                = 0x05
LANG_DANISH                               = 0x06
LANG_DARI                                 = 0x8c
LANG_DIVEHI                               = 0x65
LANG_DUTCH                                = 0x13
LANG_ENGLISH                              = 0x09
LANG_ESTONIAN                             = 0x25
LANG_FAEROESE                             = 0x38
LANG_FARSI                                = 0x29
LANG_FILIPINO                             = 0x64
LANG_FINNISH                              = 0x0b
LANG_FRENCH                               = 0x0c
LANG_FRISIAN                              = 0x62
LANG_FULAH				                  = 0x67
LANG_GALICIAN                             = 0x56
LANG_GEORGIAN                             = 0x37
LANG_GERMAN                               = 0x07
LANG_GREEK                                = 0x08
LANG_GREENLANDIC                          = 0x6f
LANG_GUJARATI                             = 0x47
LANG_HAUSA                                = 0x68
LANG_HAWAIIAN                             = 0x75
LANG_HEBREW                               = 0x0d
LANG_HINDI                                = 0x39
LANG_HUNGARIAN                            = 0x0e
LANG_ICELANDIC                            = 0x0f
LANG_IGBO                                 = 0x70
LANG_INDONESIAN                           = 0x21
LANG_INUKTITUT                            = 0x5d
LANG_IRISH                                = 0x3c
LANG_ITALIAN                              = 0x10
LANG_JAPANESE                             = 0x11
LANG_KANNADA                              = 0x4b
LANG_KASHMIRI                             = 0x60
LANG_KAZAK                                = 0x3f
LANG_KHMER                                = 0x53
LANG_KICHE                                = 0x86
LANG_KINYARWANDA                          = 0x87
LANG_KONKANI                              = 0x57
LANG_KOREAN                               = 0x12
LANG_KYRGYZ                               = 0x40
LANG_LAO                                  = 0x54
LANG_LATVIAN                              = 0x26
LANG_LITHUANIAN                           = 0x27
LANG_LOWER_SORBIAN                        = 0x2e
LANG_LUXEMBOURGISH                        = 0x6e
LANG_MACEDONIAN                           = 0x2f
LANG_MALAY                                = 0x3e
LANG_MALAYALAM                            = 0x4c
LANG_MALTESE                              = 0x3a
LANG_MANIPURI                             = 0x58
LANG_MAORI                                = 0x81
LANG_MAPUDUNGUN                           = 0x7a
LANG_MARATHI                              = 0x4e
LANG_MOHAWK                               = 0x7c
LANG_MONGOLIAN                            = 0x50
LANG_NEPALI                               = 0x61
LANG_NORWEGIAN                            = 0x14
LANG_OCCITAN                              = 0x82
LANG_ODIA				                  = 0x48
LANG_ORIYA                                = 0x48
LANG_PASHTO                               = 0x63
LANG_PERSIAN                              = 0x29
LANG_POLISH                               = 0x15
LANG_PORTUGUESE                           = 0x16
LANG_PULAR				  = 0x67
LANG_PUNJABI                              = 0x46
LANG_QUECHUA                              = 0x6b
LANG_ROMANIAN                             = 0x18
LANG_ROMANSH                              = 0x17
LANG_RUSSIAN                              = 0x19
LANG_SAKHA				  = 0x85
LANG_SAMI                                 = 0x3b
LANG_SANSKRIT                             = 0x4f
LANG_SCOTTISH_GAELIC			  = 0x91
LANG_SERBIAN                              = 0x1a
LANG_SERBIAN_NEUTRAL                    = 0x7c1a
LANG_SINDHI                               = 0x59
LANG_SINHALESE                            = 0x5b
LANG_SLOVAK                               = 0x1b
LANG_SLOVENIAN                            = 0x24
LANG_SOTHO                                = 0x6c
LANG_SPANISH                              = 0x0a
LANG_SWAHILI                              = 0x41
LANG_SWEDISH                              = 0x1d
LANG_SYRIAC                               = 0x5a
LANG_TAJIK                                = 0x28
LANG_TAMAZIGHT                            = 0x5f
LANG_TAMIL                                = 0x49
LANG_TATAR                                = 0x44
LANG_TELUGU                               = 0x4a
LANG_THAI                                 = 0x1e
LANG_TIBETAN                              = 0x51
LANG_TIGRIGNA                             = 0x73
LANG_TIGRINYA				  = 0x73
LANG_TSWANA                               = 0x32
LANG_TURKISH                              = 0x1f
LANG_TURKMEN                              = 0x42
LANG_UIGHUR                               = 0x80
LANG_UKRAINIAN                            = 0x22
LANG_UPPER_SORBIAN                        = 0x2e
LANG_URDU                                 = 0x20
LANG_UZBEK                                = 0x43
LANG_VALENCIAN				  = 0x03
LANG_VIETNAMESE                           = 0x2a
LANG_WELSH                                = 0x52
LANG_WOLOF                                = 0x88
LANG_XHOSA                                = 0x34
LANG_YAKUT                                = 0x85
LANG_YI                                   = 0x78
LANG_YORUBA                               = 0x6a
LANG_ZULU                                 = 0x35

SUBLANG_NEUTRAL                           = 0x00
SUBLANG_DEFAULT                           = 0x01
SUBLANG_SYS_DEFAULT                       = 0x02
SUBLANG_CUSTOM_DEFAULT                    = 0x03
SUBLANG_CUSTOM_UNSPECIFIED                = 0x04
SUBLANG_UI_CUSTOM_DEFAULT                 = 0x05

SUBLANG_AFRIKAANS_SOUTH_AFRICA            = 0x01
SUBLANG_ALBANIAN_ALBANIA                  = 0x01
SUBLANG_ALSATIAN_FRANCE                   = 0x01
SUBLANG_AMHARIC_ETHIOPIA                  = 0x01
SUBLANG_ARABIC_SAUDI_ARABIA               = 0x01
SUBLANG_ARABIC_IRAQ                       = 0x02
SUBLANG_ARABIC_EGYPT                      = 0x03
SUBLANG_ARABIC_LIBYA                      = 0x04
SUBLANG_ARABIC_ALGERIA                    = 0x05
SUBLANG_ARABIC_MOROCCO                    = 0x06
SUBLANG_ARABIC_TUNISIA                    = 0x07
SUBLANG_ARABIC_OMAN                       = 0x08
SUBLANG_ARABIC_YEMEN                      = 0x09
SUBLANG_ARABIC_SYRIA                      = 0x0a
SUBLANG_ARABIC_JORDAN                     = 0x0b
SUBLANG_ARABIC_LEBANON                    = 0x0c
SUBLANG_ARABIC_KUWAIT                     = 0x0d
SUBLANG_ARABIC_UAE                        = 0x0e
SUBLANG_ARABIC_BAHRAIN                    = 0x0f
SUBLANG_ARABIC_QATAR                      = 0x10
SUBLANG_ARMENIAN_ARMENIA                  = 0x01
SUBLANG_ASSAMESE_INDIA                    = 0x01
SUBLANG_AZERI_LATIN                       = 0x01
SUBLANG_AZERI_CYRILLIC                    = 0x02
SUBLANG_AZERBAIJANI_AZERBAIJAN_LATIN      = 0x01
SUBLANG_AZERBAIJANI_AZERBAIJAN_CYRILLIC   = 0x02
SUBLANG_BANGLA_INDIA                      = 0x01
SUBLANG_BANGLA_BANGLADESH                 = 0x02
SUBLANG_BASHKIR_RUSSIA                    = 0x01
SUBLANG_BASQUE_BASQUE                     = 0x01
SUBLANG_BELARUSIAN_BELARUS                = 0x01
SUBLANG_BENGALI_INDIA                     = 0x01
SUBLANG_BENGALI_BANGLADESH                = 0x02
SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_LATIN  = 0x05
SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC = 0x08
SUBLANG_BRETON_FRANCE                     = 0x01
SUBLANG_BULGARIAN_BULGARIA                = 0x01
SUBLANG_CATALAN_CATALAN                   = 0x01
SUBLANG_CENTRAL_KURDISH_IRAQ              = 0x01
SUBLANG_CHEROKEE_CHEROKEE                 = 0x01
SUBLANG_CHINESE_TRADITIONAL               = 0x01
SUBLANG_CHINESE_SIMPLIFIED                = 0x02
SUBLANG_CHINESE_HONGKONG                  = 0x03
SUBLANG_CHINESE_SINGAPORE                 = 0x04
SUBLANG_CHINESE_MACAU                     = 0x05
SUBLANG_CORSICAN_FRANCE                   = 0x01
SUBLANG_CZECH_CZECH_REPUBLIC              = 0x01
SUBLANG_CROATIAN_CROATIA                  = 0x01
SUBLANG_CROATIAN_BOSNIA_HERZEGOVINA_LATIN = 0x04
SUBLANG_DANISH_DENMARK                    = 0x01
SUBLANG_DARI_AFGHANISTAN                  = 0x01
SUBLANG_DIVEHI_MALDIVES                   = 0x01
SUBLANG_DUTCH                             = 0x01
SUBLANG_DUTCH_BELGIAN                     = 0x02
SUBLANG_ENGLISH_US                        = 0x01
SUBLANG_ENGLISH_UK                        = 0x02
SUBLANG_ENGLISH_AUS                       = 0x03
SUBLANG_ENGLISH_CAN                       = 0x04
SUBLANG_ENGLISH_NZ                        = 0x05
SUBLANG_ENGLISH_IRELAND                   = 0x06
SUBLANG_ENGLISH_EIRE                      = 0x06
SUBLANG_ENGLISH_SOUTH_AFRICA              = 0x07
SUBLANG_ENGLISH_JAMAICA                   = 0x08
SUBLANG_ENGLISH_CARIBBEAN                 = 0x09
SUBLANG_ENGLISH_BELIZE                    = 0x0a
SUBLANG_ENGLISH_TRINIDAD                  = 0x0b
SUBLANG_ENGLISH_ZIMBABWE                  = 0x0c
SUBLANG_ENGLISH_PHILIPPINES               = 0x0d
SUBLANG_ENGLISH_INDIA                     = 0x10
SUBLANG_ENGLISH_MALAYSIA                  = 0x11
SUBLANG_ENGLISH_SINGAPORE                 = 0x12
SUBLANG_ESTONIAN_ESTONIA                  = 0x01
SUBLANG_FAEROESE_FAROE_ISLANDS            = 0x01
SUBLANG_FILIPINO_PHILIPPINES              = 0x01
SUBLANG_FINNISH_FINLAND                   = 0x01
SUBLANG_FRENCH                            = 0x01
SUBLANG_FRENCH_BELGIAN                    = 0x02
SUBLANG_FRENCH_CANADIAN                   = 0x03
SUBLANG_FRENCH_SWISS                      = 0x04
SUBLANG_FRENCH_LUXEMBOURG                 = 0x05
SUBLANG_FRENCH_MONACO                     = 0x06
SUBLANG_FRISIAN_NETHERLANDS               = 0x01
SUBLANG_FULAH_SENEGAL                     = 0x02
SUBLANG_GALICIAN_GALICIAN                 = 0x01
SUBLANG_GEORGIAN_GEORGIA                  = 0x01
SUBLANG_GERMAN                            = 0x01
SUBLANG_GERMAN_SWISS                      = 0x02
SUBLANG_GERMAN_AUSTRIAN                   = 0x03
SUBLANG_GERMAN_LUXEMBOURG                 = 0x04
SUBLANG_GERMAN_LIECHTENSTEIN              = 0x05
SUBLANG_GREEK_GREECE                      = 0x01
SUBLANG_GREENLANDIC_GREENLAND             = 0x01
SUBLANG_GUJARATI_INDIA                    = 0x01
SUBLANG_HAUSA_NIGERIA_LATIN               = 0x01

SUBLANG_HAWAIIAN_US                       = 0x01
SUBLANG_HEBREW_ISRAEL                     = 0x01
SUBLANG_HINDI_INDIA                       = 0x01
SUBLANG_HUNGARIAN_HUNGARY                 = 0x01
SUBLANG_ICELANDIC_ICELAND                 = 0x01
SUBLANG_IGBO_NIGERIA                      = 0x01
SUBLANG_INDONESIAN_INDONESIA              = 0x01
SUBLANG_INUKTITUT_CANADA                  = 0x01
SUBLANG_INUKTITUT_CANADA_LATIN            = 0x02
SUBLANG_IRISH_IRELAND                     = 0x02
SUBLANG_ITALIAN                           = 0x01
SUBLANG_ITALIAN_SWISS                     = 0x02
SUBLANG_JAPANESE_JAPAN                    = 0x01
SUBLANG_KANNADA_INDIA                     = 0x01
SUBLANG_KASHMIRI_INDIA                    = 0x02
SUBLANG_KASHMIRI_SASIA                    = 0x02
SUBLANG_KAZAK_KAZAKHSTAN                  = 0x01
SUBLANG_KHMER_CAMBODIA                    = 0x01
SUBLANG_KICHE_GUATEMALA                   = 0x01
SUBLANG_KINYARWANDA_RWANDA                = 0x01
SUBLANG_KONKANI_INDIA                     = 0x01
SUBLANG_KOREAN                            = 0x01
SUBLANG_KYRGYZ_KYRGYZSTAN                 = 0x01
SUBLANG_LAO_LAO                           = 0x01

SUBLANG_LATVIAN_LATVIA                    = 0x01

SUBLANG_LITHUANIAN_LITHUANIA              = 0x01

SUBLANG_LITHUANIAN                        = 0x01
SUBLANG_LOWER_SORBIAN_GERMANY             = 0x02
SUBLANG_LUXEMBOURGISH_LUXEMBOURG          = 0x01
SUBLANG_MACEDONIAN_MACEDONIA              = 0x01
SUBLANG_MALAY_MALAYSIA                    = 0x01
SUBLANG_MALAY_BRUNEI_DARUSSALAM           = 0x02
SUBLANG_MALAYALAM_INDIA                   = 0x01
SUBLANG_MALTESE_MALTA                     = 0x01
SUBLANG_MAORI_NEW_ZEALAND                 = 0x01
SUBLANG_MAPUDUNGUN_CHILE                  = 0x01
SUBLANG_MARATHI_INDIA                     = 0x01
SUBLANG_MOHAWK_MOHAWK                     = 0x01
SUBLANG_MONGOLIAN_CYRILLIC_MONGOLIA       = 0x01
SUBLANG_MONGOLIAN_PRC                     = 0x02
SUBLANG_NEPALI_NEPAL                      = 0x01
SUBLANG_NEPALI_INDIA                      = 0x02
SUBLANG_NORWEGIAN_BOKMAL                  = 0x01
SUBLANG_NORWEGIAN_NYNORSK                 = 0x02
SUBLANG_OCCITAN_FRANCE                    = 0x01
SUBLANG_ODIA_INDIA                        = 0x01
SUBLANG_ORIYA_INDIA                       = 0x01
SUBLANG_PASHTO_AFGHANISTAN                = 0x01
SUBLANG_PERSIAN_IRAN                      = 0x01
SUBLANG_POLISH_POLAND                     = 0x01
SUBLANG_PORTUGUESE_BRAZILIAN              = 0x01

SUBLANG_PORTUGUESE_PORTUGAL               = 0x02

SUBLANG_PORTUGUESE                        = 0x02
SUBLANG_PULAR_SENEGAL                     = 0x02
SUBLANG_PUNJABI_INDIA                     = 0x01
SUBLANG_PUNJABI_PAKISTAN                  = 0x02
SUBLANG_QUECHUA_BOLIVIA                   = 0x01
SUBLANG_QUECHUA_ECUADOR                   = 0x02
SUBLANG_QUECHUA_PERU                      = 0x03
SUBLANG_ROMANIAN_ROMANIA                  = 0x01

SUBLANG_ROMANSH_SWITZERLAND               = 0x01
SUBLANG_RUSSIAN_RUSSIA                    = 0x01
SUBLANG_SAKHA_RUSSIA                      = 0x01
SUBLANG_SAMI_NORTHERN_NORWAY              = 0x01
SUBLANG_SAMI_NORTHERN_SWEDEN              = 0x02
SUBLANG_SAMI_NORTHERN_FINLAND             = 0x03
SUBLANG_SAMI_LULE_NORWAY                  = 0x04
SUBLANG_SAMI_LULE_SWEDEN                  = 0x05
SUBLANG_SAMI_SOUTHERN_NORWAY              = 0x06
SUBLANG_SAMI_SOUTHERN_SWEDEN              = 0x07
SUBLANG_SAMI_SKOLT_FINLAND                = 0x08
SUBLANG_SAMI_INARI_FINLAND                = 0x09
SUBLANG_SANSKRIT_INDIA                    = 0x01
SUBLANG_SCOTTISH_GAELIC                    = 0x01
SUBLANG_SERBIAN_LATIN                     = 0x02
SUBLANG_SERBIAN_CYRILLIC                  = 0x03
SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_LATIN  = 0x06
SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC = 0x07
SUBLANG_SERBIAN_MONTENEGRO_LATIN          = 0x0b
SUBLANG_SERBIAN_MONTENEGRO_CYRILLIC       = 0x0c
SUBLANG_SERBIAN_SERBIA_LATIN              = 0x09
SUBLANG_SERBIAN_SERBIA_CYRILLIC           = 0x0a
SUBLANG_SERBIAN_CROATIA                   = 0x01
SUBLANG_SINDHI_INDIA                      = 0x01
SUBLANG_SINDHI_AFGHANISTAN                = 0x02
SUBLANG_SINDHI_PAKISTAN                   = 0x02
SUBLANG_SINHALESE_SRI_LANKA               = 0x01
SUBLANG_SOTHO_NORTHERN_SOUTH_AFRICA       = 0x01
SUBLANG_SLOVAK_SLOVAKIA                   = 0x01
SUBLANG_SLOVENIAN_SLOVENIA                = 0x01
SUBLANG_SPANISH                           = 0x01
SUBLANG_SPANISH_MEXICAN                   = 0x02
SUBLANG_SPANISH_MODERN                    = 0x03
SUBLANG_SPANISH_GUATEMALA                 = 0x04
SUBLANG_SPANISH_COSTA_RICA                = 0x05
SUBLANG_SPANISH_PANAMA                    = 0x06
SUBLANG_SPANISH_DOMINICAN_REPUBLIC        = 0x07
SUBLANG_SPANISH_VENEZUELA                 = 0x08
SUBLANG_SPANISH_COLOMBIA                  = 0x09
SUBLANG_SPANISH_PERU                      = 0x0a
SUBLANG_SPANISH_ARGENTINA                 = 0x0b
SUBLANG_SPANISH_ECUADOR                   = 0x0c
SUBLANG_SPANISH_CHILE                     = 0x0d
SUBLANG_SPANISH_URUGUAY                   = 0x0e
SUBLANG_SPANISH_PARAGUAY                  = 0x0f
SUBLANG_SPANISH_BOLIVIA                   = 0x10
SUBLANG_SPANISH_EL_SALVADOR               = 0x11
SUBLANG_SPANISH_HONDURAS                  = 0x12
SUBLANG_SPANISH_NICARAGUA                 = 0x13
SUBLANG_SPANISH_PUERTO_RICO               = 0x14
SUBLANG_SPANISH_US                        = 0x15
SUBLANG_SWAHILI_KENYA                     = 0x01

SUBLANG_SWEDISH_SWEDEN                    = 0x01

SUBLANG_SWEDISH                           = 0x01
SUBLANG_SWEDISH_FINLAND                   = 0x02
SUBLANG_SYRIAC                            = 0x01

SUBLANG_TAJIK_TAJIKISTAN                  = 0x01
SUBLANG_TAMAZIGHT_ALGERIA_LATIN           = 0x02
SUBLANG_TAMAZIGHT_MOROCCO_TIFINAGH        = 0x04
SUBLANG_TAMIL_INDIA                       = 0x01
SUBLANG_TAMIL_SRI_LANKA                   = 0x02
SUBLANG_TATAR_RUSSIA                      = 0x01
SUBLANG_TELUGU_INDIA                      = 0x01
SUBLANG_THAI_THAILAND                     = 0x01
SUBLANG_TIBETAN_PRC                       = 0x01
SUBLANG_TIBETAN_BHUTAN                    = 0x02
SUBLANG_TIGRIGNA_ERITREA                  = 0x02
SUBLANG_TIGRINYA_ERITREA                  = 0x02
SUBLANG_TIGRINYA_ETHIOPIA                 = 0x01
SUBLANG_TSWANA_BOTSWANA                   = 0x02
SUBLANG_TSWANA_SOUTH_AFRICA               = 0x01
SUBLANG_TURKISH_TURKEY                    = 0x01
SUBLANG_TURKMEN_TURKMENISTAN              = 0x01
SUBLANG_UIGHUR_PRC                        = 0x01
SUBLANG_UKRAINIAN_UKRAINE                 = 0x01
SUBLANG_UPPER_SORBIAN_GERMANY             = 0x01
SUBLANG_URDU_PAKISTAN                     = 0x01
SUBLANG_URDU_INDIA                        = 0x02
SUBLANG_UZBEK_LATIN                       = 0x01
SUBLANG_UZBEK_CYRILLIC                    = 0x02
SUBLANG_VALENCIAN_VALENCIA                = 0x02
SUBLANG_VIETNAMESE_VIETNAM                = 0x01
SUBLANG_WELSH_UNITED_KINGDOM              = 0x01
SUBLANG_WOLOF_SENEGAL                     = 0x01
SUBLANG_YORUBA_NIGERIA                    = 0x01
SUBLANG_XHOSA_SOUTH_AFRICA                = 0x01
SUBLANG_YAKUT_RUSSIA                      = 0x01
SUBLANG_YI_PRC                            = 0x01
SUBLANG_ZULU_SOUTH_AFRICA                 = 0x01

SORT_DEFAULT                              = 0x0
SORT_INVARIANT_MATH                       = 0x1

SORT_JAPANESE_XJIS                        = 0x0
SORT_JAPANESE_UNICODE                     = 0x1
SORT_JAPANESE_RADICALSTROKE               = 0x4

SORT_CHINESE_BIG5                         = 0x0
SORT_CHINESE_PRCP                         = 0x0
SORT_CHINESE_UNICODE                      = 0x1
SORT_CHINESE_PRC                          = 0x2
SORT_CHINESE_BOPOMOFO                     = 0x3
SORT_CHINESE_RADICALSTROKE		  = 0x4

SORT_KOREAN_KSC                           = 0x0
SORT_KOREAN_UNICODE                       = 0x1

SORT_GERMAN_PHONE_BOOK                    = 0x1

SORT_HUNGARIAN_DEFAULT                    = 0x0
SORT_HUNGARIAN_TECHNICAL                  = 0x1

SORT_GEORGIAN_TRADITIONAL                 = 0x0
SORT_GEORGIAN_MODERN                      = 0x1


def MAKELANGID(p: int, s: int) -> int:
    return (WORD(s).value << 10) | WORD(p).value


def PRIMARYLANGID(lgid: int) -> int:
    return WORD(lgid).value & 0x3ff


def SUBLANGID(lgid: int) -> int:
    return WORD(lgid).value >> 10


NLS_VALID_LOCALE_MASK = 0x000fffff


def MAKELCID(lgid: int, srtid: int) -> int:
    srtid = DWORD(WORD(srtid).value).value << 16
    lgid = DWORD(WORD(lgid).value).value
    return srtid | lgid


def MAKESORTLCID(lgid: int, srtid: int, ver: int) -> int:
    res = DWORD(MAKELCID(lgid, srtid)).value
    ver = DWORD(WORD(ver).value).value  << 20
    return res | ver


def LANGIDFROMLCID(lcid: int) -> int:
    return WORD(lcid).value


def SORTIDFROMLCID(lcid: int) -> int:
    lcid = WORD(DWORD(lcid).value).value >> 16
    return lcid & 0xf


def SORTVERSIONFROMLCID(lcid: int) -> int:
    lcid = WORD(DWORD(lcid).value).value >> 20
    return lcid & 0xf


LOCALE_NAME_MAX_LENGTH = 85

LANG_SYSTEM_DEFAULT = MAKELANGID(LANG_NEUTRAL, SUBLANG_SYS_DEFAULT)
LANG_USER_DEFAULT = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)

LOCALE_SYSTEM_DEFAULT = MAKELCID(LANG_SYSTEM_DEFAULT, SORT_DEFAULT)
LOCALE_USER_DEFAULT = MAKELCID(LANG_USER_DEFAULT, SORT_DEFAULT)

LOCALE_NEUTRAL = MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), SORT_DEFAULT)

LOCALE_CUSTOM_DEFAULT = MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_CUSTOM_DEFAULT), SORT_DEFAULT)
LOCALE_CUSTOM_UNSPECIFIED = MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_CUSTOM_UNSPECIFIED), SORT_DEFAULT)
LOCALE_CUSTOM_UI_DEFAULT = MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_UI_CUSTOM_DEFAULT), SORT_DEFAULT)

LOCALE_INVARIANT = MAKELCID(MAKELANGID(LANG_INVARIANT, SUBLANG_NEUTRAL), SORT_DEFAULT)

LOCALE_TRANSIENT_KEYBOARD1 = 0x2000
LOCALE_TRANSIENT_KEYBOARD2 = 0x2400
LOCALE_TRANSIENT_KEYBOARD3 = 0x2800
LOCALE_TRANSIENT_KEYBOARD4 = 0x2c00

LOCALE_UNASSIGNED_LCID = LOCALE_CUSTOM_UNSPECIFIED


def UNREFERENCED_PARAMETER(P):
    return VOID(P).value


def UNREFERENCED_LOCAL_VARIABLE(V):
    return VOID(V).value


def __DBG_UNREFERENCED_PARAMETER__(P):
    return P


def __DBG_UNREFERENCED_LOCAL_VARIABLE__(V):
    return V


STATUS_WAIT_0 = DWORD(0x00000000).value
STATUS_ABANDONED_WAIT_0 = DWORD(0x00000080).value
STATUS_USER_APC = DWORD(0x000000C0).value
STATUS_TIMEOUT = DWORD(0x00000102).value
STATUS_PENDING = DWORD(0x00000103).value
__DBG_EXCEPTION_HANDLED__ = DWORD(0x00010001).value
__DBG_CONTINUE__ = DWORD(0x00010002).value
STATUS_SEGMENT_NOTIFICATION = DWORD(0x40000005).value
STATUS_FATAL_APP_EXIT = DWORD(0x40000015).value
__DBG_REPLY_LATER__ = DWORD(0x40010001).value
__DBG_TERMINATE_THREAD__ = DWORD(0x40010003).value
__DBG_TERMINATE_PROCESS__ = DWORD(0x40010004).value
__DBG_CONTROL_C__ = DWORD(0x40010005).value
__DBG_PRINTEXCEPTION_C__ = DWORD(0x40010006).value
__DBG_RIPEXCEPTION__ = DWORD(0x40010007).value
__DBG_CONTROL_BREAK__ = DWORD(0x40010008).value
__DBG_COMMAND_EXCEPTION__ = DWORD(0x40010009).value
__DBG_PRINTEXCEPTION_WIDE_C__ = DWORD(0x4001000A).value
STATUS_GUARD_PAGE_VIOLATION = DWORD(0x80000001).value
STATUS_DATATYPE_MISALIGNMENT = DWORD(0x80000002).value
STATUS_BREAKPOINT = DWORD(0x80000003).value
STATUS_SINGLE_STEP = DWORD(0x80000004).value
STATUS_LONGJUMP = DWORD(0x80000026).value
STATUS_UNWIND_CONSOLIDATE = DWORD(0x80000029).value
__DBG_EXCEPTION_NOT_HANDLED__ = DWORD(0x80010001).value
STATUS_ACCESS_VIOLATION = DWORD(0xC0000005).value
STATUS_IN_PAGE_ERROR = DWORD(0xC0000006).value
STATUS_INVALID_HANDLE = DWORD(0xC0000008).value
STATUS_INVALID_PARAMETER = DWORD(0xC000000D).value
STATUS_NO_MEMORY = DWORD(0xC0000017).value
STATUS_ILLEGAL_INSTRUCTION = DWORD(0xC000001D).value
STATUS_NONCONTINUABLE_EXCEPTION = DWORD(0xC0000025).value
STATUS_INVALID_DISPOSITION = DWORD(0xC0000026).value
STATUS_ARRAY_BOUNDS_EXCEEDED = DWORD(0xC000008C).value
STATUS_FLOAT_DENORMAL_OPERAND = DWORD(0xC000008D).value
STATUS_FLOAT_DIVIDE_BY_ZERO = DWORD(0xC000008E).value
STATUS_FLOAT_INEXACT_RESULT = DWORD(0xC000008F).value
STATUS_FLOAT_INVALID_OPERATION = DWORD(0xC0000090).value
STATUS_FLOAT_OVERFLOW = DWORD(0xC0000091).value
STATUS_FLOAT_STACK_CHECK = DWORD(0xC0000092).value
STATUS_FLOAT_UNDERFLOW = DWORD(0xC0000093).value
STATUS_INTEGER_DIVIDE_BY_ZERO = DWORD(0xC0000094).value
STATUS_INTEGER_OVERFLOW = DWORD(0xC0000095).value
STATUS_PRIVILEGED_INSTRUCTION = DWORD(0xC0000096).value
STATUS_STACK_OVERFLOW = DWORD(0xC00000FD).value
STATUS_DLL_NOT_FOUND = DWORD(0xC0000135).value
STATUS_ORDINAL_NOT_FOUND = DWORD(0xC0000138).value
STATUS_ENTRYPOINT_NOT_FOUND = DWORD(0xC0000139).value
STATUS_CONTROL_C_EXIT = DWORD(0xC000013A).value
STATUS_DLL_INIT_FAILED = DWORD(0xC0000142).value
STATUS_CONTROL_STACK_VIOLATION = DWORD(0xC00001B2).value
STATUS_FLOAT_MULTIPLE_FAULTS = DWORD(0xC00002B4).value
STATUS_FLOAT_MULTIPLE_TRAPS = DWORD(0xC00002B5).value
STATUS_REG_NAT_CONSUMPTION = DWORD(0xC00002C9).value
STATUS_HEAP_CORRUPTION = DWORD(0xC0000374).value
STATUS_STACK_BUFFER_OVERRUN = DWORD(0xC0000409).value
STATUS_INVALID_CRUNTIME_PARAMETER = DWORD(0xC0000417).value
STATUS_ASSERTION_FAILURE = DWORD(0xC0000420).value
STATUS_ENCLAVE_VIOLATION = DWORD(0xC00004A2).value
STATUS_INTERRUPTED = DWORD(0xC0000515).value
STATUS_THREAD_NOT_RUNNING = DWORD(0xC0000516).value
STATUS_ALREADY_REGISTERED = DWORD(0xC0000718).value

STATUS_SXS_EARLY_DEACTIVATION = DWORD(0xC015000F).value
STATUS_SXS_INVALID_DEACTIVATION = DWORD(0xC0150010).value

MAXIMUM_WAIT_OBJECTS = 64
MAXIMUM_SUSPEND_COUNT = MAXCHAR

EXCEPTION_READ_FAULT = 0
EXCEPTION_WRITE_FAULT = 1
EXCEPTION_EXECUTE_FAULT = 8

CONTEXT_AMD64 = 0x100000

CONTEXT_CONTROL = (CONTEXT_AMD64 | 0x1)
CONTEXT_INTEGER = (CONTEXT_AMD64 | 0x2)
CONTEXT_SEGMENTS = (CONTEXT_AMD64 | 0x4)
CONTEXT_FLOATING_POINT = (CONTEXT_AMD64 | 0x8)
CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x10)

CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

CONTEXT_XSTATE = (CONTEXT_AMD64 | 0x40)
CONTEXT_KERNEL_CET = (CONTEXT_AMD64 | 0x80)

CONTEXT_EXCEPTION_ACTIVE = 0x8000000
CONTEXT_SERVICE_ACTIVE = 0x10000000
CONTEXT_EXCEPTION_REQUEST = 0x40000000
CONTEXT_EXCEPTION_REPORTING = 0x80000000
CONTEXT_UNWOUND_TO_CALL = 0x20000000

INITIAL_MXCSR = 0x1f80
INITIAL_FPCSR = 0x027f

OUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK_EXPORT_NAME = "OutOfProcessFunctionTableCallback"

UNW_FLAG_NHANDLER =   0x0
UNW_FLAG_EHANDLER =   0x1
UNW_FLAG_UHANDLER =   0x2
UNW_FLAG_CHAININFO =  0x4

class _LDT_ENTRY(Structure):
    class HighWord(Union):
        class Bytes(Structure):
            _fields_ = [('BaseMid', BYTE),
                        ('Flags1', BYTE),
                        ('Flags2', BYTE),
                        ('BaseHi', BYTE),
            ]
        
        class Bits(LittleEndianStructure):
            _fields_ = [('BaseMid', DWORD, 8),
                        ('Type', DWORD, 5),
                        ('Dpl', DWORD, 2),
                        ('Pres', DWORD, 1),
                        ('LimitHi', DWORD, 4),
                        ('Sys', DWORD, 1),
                        ('Reserved_0', DWORD, 1),
                        ('Default_Big', DWORD, 1),
                        ('Granularity', DWORD, 1),
                        ('BaseHi', DWORD, 8)
            ]
        
        _anonymous_ = ['Bytes', 'Bits']
        _fields_ = [('Bytes', Bytes),
                    ('Bits', Bits)
        ]

    _anonymous_ = ['HighWord']
    _fields_ = [('LimitLow', WORD),
                ('BaseLow', WORD),
                ('HighWord', HighWord)
    ]

LDT_ENTRY = _LDT_ENTRY
PLDT_ENTRY = POINTER(LDT_ENTRY)

EXCEPTION_NONCONTINUABLE = 0x1
EXCEPTION_UNWINDING =	   0x2
EXCEPTION_EXIT_UNWIND =      0x4
EXCEPTION_STACK_INVALID =    0x8
EXCEPTION_NESTED_CALL =      0x10
EXCEPTION_TARGET_UNWIND =    0x20
EXCEPTION_COLLIDED_UNWIND =  0x40
EXCEPTION_UNWIND =           0x66


def IS_UNWINDING(f: int) -> bool:
    return (f & EXCEPTION_UNWIND) != 0


def IS_DISPATCHING(f: int) -> bool:
    return (f & EXCEPTION_UNWIND) == 0


def IS_TARGET_UNWIND(f: int) -> bool:
    return (f & EXCEPTION_TARGET_UNWIND) != 0


UNWIND_HISTORY_TABLE_SIZE = 12

class _UNWIND_HISTORY_TABLE_ENTRY(Structure):
    _fields_ = [('ImageBase', ULONG64),
                ('FunctionEntry', PRUNTIME_FUNCTION)
    ]

UNWIND_HISTORY_TABLE_ENTRY = _UNWIND_HISTORY_TABLE_ENTRY
PUNWIND_HISTORY_TABLE_ENTRY = POINTER(UNWIND_HISTORY_TABLE_ENTRY)

UNWIND_HISTORY_TABLE_NONE =    0
UNWIND_HISTORY_TABLE_GLOBAL =  1
UNWIND_HISTORY_TABLE_LOCAL =   2

class _UNWIND_HISTORY_TABLE(Structure):
    _fields_ = [('Count', ULONG),
                ('LocalHint', BYTE),
                ('GlobalHint', BYTE),
                ('Search', BYTE),
                ('Once', BYTE),
                ('LowAddress', ULONG64),
                ('HighAddress', ULONG64),
                ('Entry', UNWIND_HISTORY_TABLE_ENTRY * UNWIND_HISTORY_TABLE_SIZE)
    ]

UNWIND_HISTORY_TABLE = _UNWIND_HISTORY_TABLE
PUNWIND_HISTORY_TABLE = POINTER(UNWIND_HISTORY_TABLE)

class _DISPATCHER_CONTEXT(Structure):
    pass

DISPATCHER_CONTEXT = _DISPATCHER_CONTEXT
PDISPATCHER_CONTEXT = POINTER(DISPATCHER_CONTEXT)

EXCEPTION_ROUTINE = CALLBACK(INT, _EXCEPTION_RECORD, PVOID, _CONTEXT, PVOID)
PEXCEPTION_ROUTINE = POINTER(EXCEPTION_ROUTINE)

class _DISPATCHER_CONTEXT(Structure):
    _fields_ = [('ControlPc', ULONG64),
                ('ImageBase', ULONG64),
                ('FunctionEntry', PRUNTIME_FUNCTION),
                ('EstablisherFrame', ULONG64),
                ('TargetIp', ULONG64),
                ('ContextRecord', PCONTEXT),
                ('LanguageHandler', PEXCEPTION_ROUTINE),
                ('HandlerData', PVOID),
                ('HistoryTable', PUNWIND_HISTORY_TABLE),
                ('ScopeIndex', ULONG),
                ('Fill0', ULONG),
    ]

class _KNONVOLATILE_CONTEXT_POINTERS(Structure):
    _fields_ = [('FloatingContext', PM128A * 16),
                ('IntegerContext', PULONG64 * 16)
    ]

KNONVOLATILE_CONTEXT_POINTERS = _KNONVOLATILE_CONTEXT_POINTERS
PKNONVOLATILE_CONTEXT_POINTERS = POINTER(KNONVOLATILE_CONTEXT_POINTERS)

PACCESS_TOKEN = PVOID
PSECURITY_DESCRIPTOR = PVOID
PSID = PVOID
PCLAIMS_BLOB = PVOID
ACCESS_MASK = DWORD
PACCESS_MASK = POINTER(ACCESS_MASK)

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

SPECIFIC_RIGHTS_ALL  = 0x0000FFFF

ACCESS_SYSTEM_SECURITY  = 0x01000000
MAXIMUM_ALLOWED  = 0x02000000

GENERIC_READ  = 0x80000000
GENERIC_WRITE  = 0x40000000
GENERIC_EXECUTE  = 0x20000000
GENERIC_ALL  = 0x10000000

class _GENERIC_MAPPING(Structure):
    _fields_ = [('GenericRead', ACCESS_MASK),
                ('GenericWrite', ACCESS_MASK),
                ('GenericExecute', ACCESS_MASK),
                ('GenericAll', ACCESS_MASK),
    ]

GENERIC_MAPPING = _GENERIC_MAPPING
PGENERIC_MAPPING = POINTER(GENERIC_MAPPING)

class _LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [('Luid', LUID),
                ('Attributes', DWORD)
    ]

LUID_AND_ATTRIBUTES = _LUID_AND_ATTRIBUTES
PLUID_AND_ATTRIBUTES = POINTER(LUID_AND_ATTRIBUTES)

class _SID_IDENTIFIER_AUTHORITY(Structure):
    _fields_ = [('Value', BYTE * 6)]

SID_IDENTIFIER_AUTHORITY = _SID_IDENTIFIER_AUTHORITY
PSID_IDENTIFIER_AUTHORITY = POINTER(SID_IDENTIFIER_AUTHORITY)

class _SID(Structure):
    _fields_ = [('Revision', BYTE),
                ('SubAuthorityCount', BYTE),
                ('IdentifierAuthority', SID_IDENTIFIER_AUTHORITY),
                ('SubAuthority', DWORD * ANYSIZE_ARRAY)
    ]

SID = _SID
PISID = POINTER(SID)

SID_REVISION = 1
SID_MAX_SUB_AUTHORITIES = 15
SID_RECOMMENDED_SUB_AUTHORITIES = 1

SECURITY_MAX_SID_SIZE = sizeof(SID()) - sizeof(DWORD()) + (SID_MAX_SUB_AUTHORITIES * sizeof(DWORD()))

SID_HASH_SIZE = 32

SidTypeUser = 1
SidTypeGroup = 2
SidTypeDomain = 3
SidTypeAlias = 4
SidTypeWellKnownGroup = 5
SidTypeDeletedAccount = 6
SidTypeInvalid = 7
SidTypeUnknown = 8
SidTypeComputer = 9
SidTypeLabel = 10
SidTypeLogonSession = 11

class _SID_NAME_USE(enum.IntFlag):
    SidTypeUser = 1
    SidTypeGroup = 2
    SidTypeDomain = 3
    SidTypeAlias = 4
    SidTypeWellKnownGroup = 5
    SidTypeDeletedAccount = 6
    SidTypeInvalid = 7
    SidTypeUnknown = 8
    SidTypeComputer = 9
    SidTypeLabel = 10
    SidTypeLogonSession = 11

SID_NAME_USE = _SID_NAME_USE
PSID_NAME_USE = SID_NAME_USE

class _SID_AND_ATTRIBUTES(Structure):
    _fields_ = [('Sid', PSID),
                ('Attributes', DWORD)
    ]

SID_AND_ATTRIBUTES = _SID_AND_ATTRIBUTES
PSID_AND_ATTRIBUTES = POINTER(SID_AND_ATTRIBUTES)

SID_HASH_ENTRY = ULONG_PTR
class _SID_AND_ATTRIBUTES_HASH(Structure):
    _fields_ = [('SidCount', DWORD),
                ('SidAttr', PSID_AND_ATTRIBUTES),
                ('Hash', SID_HASH_ENTRY * SID_HASH_SIZE)
    ]

SID_AND_ATTRIBUTES_HASH = _SID_AND_ATTRIBUTES_HASH
PSID_AND_ATTRIBUTES_HASH = POINTER(SID_AND_ATTRIBUTES_HASH)

SECURITY_NULL_SID_AUTHORITY = [0,0,0,0,0,0]
SECURITY_WORLD_SID_AUTHORITY = [0,0,0,0,0,1]
SECURITY_LOCAL_SID_AUTHORITY = [0,0,0,0,0,2]
SECURITY_CREATOR_SID_AUTHORITY = [0,0,0,0,0,3]
SECURITY_NON_UNIQUE_AUTHORITY = [0,0,0,0,0,4]
SECURITY_RESOURCE_MANAGER_AUTHORITY = [0,0,0,0,0,9]

SECURITY_NULL_RID = 0x00000000
SECURITY_WORLD_RID = 0x00000000
SECURITY_LOCAL_RID = 0x00000000
SECURITY_LOCAL_LOGON_RID = 0x00000001

SECURITY_CREATOR_OWNER_RID = 0x00000000
SECURITY_CREATOR_GROUP_RID = 0x00000001
SECURITY_CREATOR_OWNER_SERVER_RID = 0x00000002
SECURITY_CREATOR_GROUP_SERVER_RID = 0x00000003
SECURITY_CREATOR_OWNER_RIGHTS_RID = 0x00000004

SECURITY_NT_AUTHORITY = [0,0,0,0,0,5]

SECURITY_DIALUP_RID = 0x00000001
SECURITY_NETWORK_RID = 0x00000002
SECURITY_BATCH_RID = 0x00000003
SECURITY_INTERACTIVE_RID = 0x00000004
SECURITY_LOGON_IDS_RID = 0x00000005
SECURITY_LOGON_IDS_RID_COUNT = 3
SECURITY_SERVICE_RID = 0x00000006
SECURITY_ANONYMOUS_LOGON_RID = 0x00000007
SECURITY_PROXY_RID = 0x00000008
SECURITY_ENTERPRISE_CONTROLLERS_RID = 0x00000009
SECURITY_SERVER_LOGON_RID = SECURITY_ENTERPRISE_CONTROLLERS_RID
SECURITY_PRINCIPAL_SELF_RID = 0x0000000A
SECURITY_AUTHENTICATED_USER_RID = 0x0000000B
SECURITY_RESTRICTED_CODE_RID = 0x0000000C
SECURITY_TERMINAL_SERVER_RID = 0x0000000D
SECURITY_REMOTE_LOGON_RID = 0x0000000E
SECURITY_THIS_ORGANIZATION_RID = 0x0000000F
SECURITY_IUSER_RID = 0x00000011
SECURITY_LOCAL_SYSTEM_RID = 0x00000012
SECURITY_LOCAL_SERVICE_RID = 0x00000013
SECURITY_NETWORK_SERVICE_RID = 0x00000014

SECURITY_NT_NON_UNIQUE = 0x00000015
SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT = 3

SECURITY_ENTERPRISE_READONLY_CONTROLLERS_RID = 0x00000016

SECURITY_BUILTIN_DOMAIN_RID = 0x00000020
SECURITY_WRITE_RESTRICTED_CODE_RID = 0x00000021

SECURITY_PACKAGE_BASE_RID = 0x00000040
SECURITY_PACKAGE_RID_COUNT = 2
SECURITY_PACKAGE_NTLM_RID = 0x0000000A
SECURITY_PACKAGE_SCHANNEL_RID = 0x0000000E
SECURITY_PACKAGE_DIGEST_RID = 0x00000015

SECURITY_CRED_TYPE_BASE_RID = 0x00000041
SECURITY_CRED_TYPE_RID_COUNT = 2
SECURITY_CRED_TYPE_THIS_ORG_CERT_RID = 0x00000001

SECURITY_MIN_BASE_RID = 0x00000050

SECURITY_SERVICE_ID_BASE_RID = 0x00000050
SECURITY_SERVICE_ID_RID_COUNT = 6

SECURITY_RESERVED_ID_BASE_RID = 0x00000051

SECURITY_APPPOOL_ID_BASE_RID = 0x00000052
SECURITY_APPPOOL_ID_RID_COUNT = 6

SECURITY_VIRTUALSERVER_ID_BASE_RID = 0x00000053
SECURITY_VIRTUALSERVER_ID_RID_COUNT = 6

SECURITY_USERMODEDRIVERHOST_ID_BASE_RID = 0x00000054
SECURITY_USERMODEDRIVERHOST_ID_RID_COUNT = 6

SECURITY_CLOUD_INFRASTRUCTURE_SERVICES_ID_BASE_RID = 0x00000055
SECURITY_CLOUD_INFRASTRUCTURE_SERVICES_ID_RID_COUNT = 6

SECURITY_WMIHOST_ID_BASE_RID = 0x00000056
SECURITY_WMIHOST_ID_RID_COUNT = 6

SECURITY_TASK_ID_BASE_RID = 0x00000057

SECURITY_NFS_ID_BASE_RID = 0x00000058

SECURITY_COM_ID_BASE_RID = 0x00000059

SECURITY_WINDOW_MANAGER_BASE_RID = 0x0000005a

SECURITY_RDV_GFX_BASE_RID = 0x0000005b

SECURITY_DASHOST_ID_BASE_RID = 0x0000005c
SECURITY_DASHOST_ID_RID_COUNT = 6

SECURITY_USERMANAGER_ID_BASE_RID = 0x0000005d
SECURITY_USERMANAGER_ID_RID_COUNT = 6

SECURITY_WINRM_ID_BASE_RID = 0x0000005e
SECURITY_WINRM_ID_RID_COUNT = 6

SECURITY_CCG_ID_BASE_RID = 0x0000005f
SECURITY_UMFD_BASE_RID = 0x00000060

SECURITY_VIRTUALACCOUNT_ID_RID_COUNT = 6

SECURITY_MAX_BASE_RID = 0x0000006f

SECURITY_MAX_ALWAYS_FILTERED = 0x000003E7
SECURITY_MIN_NEVER_FILTERED = 0x000003E8

SECURITY_OTHER_ORGANIZATION_RID = 0x000003E8

SECURITY_WINDOWSMOBILE_ID_BASE_RID = 0x00000070

SECURITY_INSTALLER_GROUP_CAPABILITY_BASE = 0x20
SECURITY_INSTALLER_GROUP_CAPABILITY_RID_COUNT = 9

SECURITY_INSTALLER_CAPABILITY_RID_COUNT = 10

SECURITY_LOCAL_ACCOUNT_RID = 0x00000071
SECURITY_LOCAL_ACCOUNT_AND_ADMIN_RID = 0x00000072

DOMAIN_GROUP_RID_AUTHORIZATION_DATA_IS_COMPOUNDED = 0x000001f0
DOMAIN_GROUP_RID_AUTHORIZATION_DATA_CONTAINS_CLAIMS = 0x000001f1
DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS = 0x000001f2

FOREST_USER_RID_MAX = 0x000001F3

DOMAIN_USER_RID_ADMIN = 0x000001F4
DOMAIN_USER_RID_GUEST = 0x000001F5
DOMAIN_USER_RID_KRBTGT = 0x000001F6
DOMAIN_USER_RID_DEFAULT_ACCOUNT = 0x000001F7
DOMAIN_USER_RID_WDAG_ACCOUNT = 0x000001F8

DOMAIN_USER_RID_MAX = 0x000003E7

DOMAIN_GROUP_RID_ADMINS = 0x00000200
DOMAIN_GROUP_RID_USERS = 0x00000201
DOMAIN_GROUP_RID_GUESTS = 0x00000202
DOMAIN_GROUP_RID_COMPUTERS = 0x00000203
DOMAIN_GROUP_RID_CONTROLLERS = 0x00000204
DOMAIN_GROUP_RID_CERT_ADMINS = 0x00000205
DOMAIN_GROUP_RID_SCHEMA_ADMINS = 0x00000206
DOMAIN_GROUP_RID_ENTERPRISE_ADMINS = 0x00000207
DOMAIN_GROUP_RID_POLICY_ADMINS = 0x00000208
DOMAIN_GROUP_RID_READONLY_CONTROLLERS = 0x00000209
DOMAIN_GROUP_RID_CLONEABLE_CONTROLLERS = 0x0000020a
DOMAIN_GROUP_RID_CDC_RESERVED = 0x0000020c
DOMAIN_GROUP_RID_PROTECTED_USERS = 0x0000020d
DOMAIN_GROUP_RID_KEY_ADMINS = 0x0000020e
DOMAIN_GROUP_RID_ENTERPRISE_KEY_ADMINS = 0x0000020f

DOMAIN_ALIAS_RID_ADMINS = 0x00000220
DOMAIN_ALIAS_RID_USERS = 0x00000221
DOMAIN_ALIAS_RID_GUESTS = 0x00000222
DOMAIN_ALIAS_RID_POWER_USERS = 0x00000223

DOMAIN_ALIAS_RID_ACCOUNT_OPS = 0x00000224
DOMAIN_ALIAS_RID_SYSTEM_OPS = 0x00000225
DOMAIN_ALIAS_RID_PRINT_OPS = 0x00000226
DOMAIN_ALIAS_RID_BACKUP_OPS = 0x00000227

DOMAIN_ALIAS_RID_REPLICATOR = 0x00000228
DOMAIN_ALIAS_RID_RAS_SERVERS = 0x00000229
DOMAIN_ALIAS_RID_PREW2KCOMPACCESS = 0x0000022A
DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS = 0x0000022B
DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS = 0x0000022C
DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS = 0x0000022D

DOMAIN_ALIAS_RID_MONITORING_USERS = 0x0000022E
DOMAIN_ALIAS_RID_LOGGING_USERS = 0x0000022F
DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS = 0x00000230
DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS = 0x00000231
DOMAIN_ALIAS_RID_DCOM_USERS = 0x00000232

DOMAIN_ALIAS_RID_IUSERS = 0x00000238
DOMAIN_ALIAS_RID_CRYPTO_OPERATORS = 0x00000239
DOMAIN_ALIAS_RID_CACHEABLE_PRINCIPALS_GROUP = 0x0000023B
DOMAIN_ALIAS_RID_NON_CACHEABLE_PRINCIPALS_GROUP = 0x0000023C
DOMAIN_ALIAS_RID_EVENT_LOG_READERS_GROUP = 0x0000023D
DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP = 0x0000023e
DOMAIN_ALIAS_RID_RDS_REMOTE_ACCESS_SERVERS = 0x0000023f
DOMAIN_ALIAS_RID_RDS_ENDPOINT_SERVERS = 0x00000240
DOMAIN_ALIAS_RID_RDS_MANAGEMENT_SERVERS = 0x00000241
DOMAIN_ALIAS_RID_HYPER_V_ADMINS = 0x00000242
DOMAIN_ALIAS_RID_ACCESS_CONTROL_ASSISTANCE_OPS = 0x00000243
DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS = 0x00000244
DOMAIN_ALIAS_RID_DEFAULT_ACCOUNT = 0x00000245
DOMAIN_ALIAS_RID_STORAGE_REPLICA_ADMINS = 0x00000246
DOMAIN_ALIAS_RID_DEVICE_OWNERS = 0x00000247

SECURITY_APP_PACKAGE_AUTHORITY = [0, 0, 0, 0, 0, 15]

SECURITY_APP_PACKAGE_BASE_RID = 0x00000002
SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT = 2
SECURITY_APP_PACKAGE_RID_COUNT = 8
SECURITY_CAPABILITY_BASE_RID = 0x00000003
SECURITY_CAPABILITY_APP_RID = 0x000000400
SECURITY_CAPABILITY_APP_SILO_RID = 0x00010000
SECURITY_BUILTIN_CAPABILITY_RID_COUNT = 2
SECURITY_CAPABILITY_RID_COUNT = 5
SECURITY_PARENT_PACKAGE_RID_COUNT = SECURITY_APP_PACKAGE_RID_COUNT
SECURITY_CHILD_PACKAGE_RID_COUNT = 12

SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE = 0x00000001
SECURITY_BUILTIN_PACKAGE_ANY_RESTRICTED_PACKAGE = 0x00000002

SECURITY_CAPABILITY_INTERNET_CLIENT = 0x00000001
SECURITY_CAPABILITY_INTERNET_CLIENT_SERVER = 0x00000002
SECURITY_CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER = 0x00000003
SECURITY_CAPABILITY_PICTURES_LIBRARY = 0x00000004
SECURITY_CAPABILITY_VIDEOS_LIBRARY = 0x00000005
SECURITY_CAPABILITY_MUSIC_LIBRARY = 0x00000006
SECURITY_CAPABILITY_DOCUMENTS_LIBRARY = 0x00000007
SECURITY_CAPABILITY_ENTERPRISE_AUTHENTICATION = 0x00000008
SECURITY_CAPABILITY_SHARED_USER_CERTIFICATES = 0x00000009
SECURITY_CAPABILITY_REMOVABLE_STORAGE = 0x0000000a
SECURITY_CAPABILITY_APPOINTMENTS = 0x0000000b
SECURITY_CAPABILITY_CONTACTS = 0x0000000c
SECURITY_CAPABILITY_INTERNET_EXPLORER = 0x00001000



SECURITY_MANDATORY_LABEL_AUTHORITY = (0,0,0,0,0,16)
SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000
SECURITY_MANDATORY_LOW_RID = 0x00001000
SECURITY_MANDATORY_MEDIUM_RID = 0x00002000
SECURITY_MANDATORY_MEDIUM_PLUS_RID = SECURITY_MANDATORY_MEDIUM_RID + 0x100
SECURITY_MANDATORY_HIGH_RID = 0x00003000
SECURITY_MANDATORY_SYSTEM_RID = 0x00004000
SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000

SECURITY_MANDATORY_MAXIMUM_USER_RID = SECURITY_MANDATORY_SYSTEM_RID

def MANDATORY_LEVEL_TO_MANDATORY_RID(IL):
    return IL * 0x1000

SECURITY_SCOPED_POLICY_ID_AUTHORITY = (0, 0, 0, 0, 0, 17)

SECURITY_AUTHENTICATION_AUTHORITY = (0, 0, 0, 0, 0, 18)
SECURITY_AUTHENTICATION_AUTHORITY_RID_COUNT = 1
SECURITY_AUTHENTICATION_AUTHORITY_ASSERTED_RID = 0x00000001
SECURITY_AUTHENTICATION_SERVICE_ASSERTED_RID = 0x00000002
SECURITY_AUTHENTICATION_FRESH_KEY_AUTH_RID = 0x00000003
SECURITY_AUTHENTICATION_KEY_TRUST_RID = 0x00000004
SECURITY_AUTHENTICATION_KEY_PROPERTY_MFA_RID = 0x00000005
SECURITY_AUTHENTICATION_KEY_PROPERTY_ATTESTATION_RID = 0x00000006

SECURITY_PROCESS_TRUST_AUTHORITY = [0, 0, 0, 0, 0, 19]
SECURITY_PROCESS_TRUST_AUTHORITY_RID_COUNT = 2

SECURITY_PROCESS_PROTECTION_TYPE_FULL_RID = 0x00000400
SECURITY_PROCESS_PROTECTION_TYPE_LITE_RID = 0x00000200
SECURITY_PROCESS_PROTECTION_TYPE_NONE_RID = 0x00000000

SECURITY_PROCESS_PROTECTION_LEVEL_WINTCB_RID = 0x00002000
SECURITY_PROCESS_PROTECTION_LEVEL_WINDOWS_RID = 0x00001000
SECURITY_PROCESS_PROTECTION_LEVEL_APP_RID = 0x00000800
SECURITY_PROCESS_PROTECTION_LEVEL_ANTIMALWARE_RID = 0x00000600
SECURITY_PROCESS_PROTECTION_LEVEL_AUTHENTICODE_RID = 0x00000400
SECURITY_PROCESS_PROTECTION_LEVEL_NONE_RID = 0x00000000

SECURITY_TRUSTED_INSTALLER_RID1 = 956008885
SECURITY_TRUSTED_INSTALLER_RID2 = 3418522649
SECURITY_TRUSTED_INSTALLER_RID3 = 1831038044
SECURITY_TRUSTED_INSTALLER_RID4 = 1853292631
SECURITY_TRUSTED_INSTALLER_RID5 = 2271478464

WinNullSid = 0
WinWorldSid = 1
WinLocalSid = 2
WinCreatorOwnerSid = 3
WinCreatorGroupSid = 4
WinCreatorOwnerServerSid = 5
WinCreatorGroupServerSid = 6
WinNtAuthoritySid = 7
WinDialupSid = 8
WinNetworkSid = 9
WinBatchSid = 10
WinInteractiveSid = 11
WinServiceSid = 12
WinAnonymousSid = 13
WinProxySid = 14
WinEnterpriseControllersSid = 15
WinSelfSid = 16,
WinAuthenticatedUserSid = 17
WinRestrictedCodeSid = 18
WinTerminalServerSid = 19
WinRemoteLogonIdSid = 20
WinLogonIdsSid = 21
WinLocalSystemSid = 22
WinLocalServiceSid = 23
WinNetworkServiceSid = 24
WinBuiltinDomainSid = 25
WinBuiltinAdministratorsSid = 26
WinBuiltinUsersSid = 27
WinBuiltinGuestsSid = 28
WinBuiltinPowerUsersSid = 29
WinBuiltinAccountOperatorsSid = 30
WinBuiltinSystemOperatorsSid = 31
WinBuiltinPrintOperatorsSid = 32
WinBuiltinBackupOperatorsSid = 33
WinBuiltinReplicatorSid = 34
WinBuiltinPreWindows2000CompatibleAccessSid = 35
WinBuiltinRemoteDesktopUsersSid = 36
WinBuiltinNetworkConfigurationOperatorsSid = 37
WinAccountAdministratorSid = 38
WinAccountGuestSid = 39
WinAccountKrbtgtSid = 40
WinAccountDomainAdminsSid = 41
WinAccountDomainUsersSid = 42
WinAccountDomainGuestsSid = 43
WinAccountComputersSid = 44
WinAccountControllersSid = 45
WinAccountCertAdminsSid = 46
WinAccountSchemaAdminsSid = 47
WinAccountEnterpriseAdminsSid = 48
WinAccountPolicyAdminsSid = 49
WinAccountRasAndIasServersSid = 50
WinNTLMAuthenticationSid = 51
WinDigestAuthenticationSid = 52
WinSChannelAuthenticationSid = 53
WinThisOrganizationSid = 54
WinOtherOrganizationSid = 55
WinBuiltinIncomingForestTrustBuildersSid = 56
WinBuiltinPerfMonitoringUsersSid = 57
WinBuiltinPerfLoggingUsersSid = 58
WinBuiltinAuthorizationAccessSid = 59
WinBuiltinTerminalServerLicenseServersSid = 60
WinBuiltinDCOMUsersSid = 61
WinBuiltinIUsersSid = 62
WinIUserSid = 63
WinBuiltinCryptoOperatorsSid = 64
WinUntrustedLabelSid = 65
WinLowLabelSid = 66 
WinMediumLabelSid = 67
WinHighLabelSid = 68
WinSystemLabelSid = 69 
WinWriteRestrictedCodeSid = 70
WinCreatorOwnerRightsSid = 71
WinCacheablePrincipalsGroupSid = 72
WinNonCacheablePrincipalsGroupSid = 73
WinEnterpriseReadonlyControllersSid = 74
WinAccountReadonlyControllersSid = 75
WinBuiltinEventLogReadersGroup = 76
WinNewEnterpriseReadonlyControllersSid = 77
WinBuiltinCertSvcDComAccessGroup = 78
WinMediumPlusLabelSid = 79
WinLocalLogonSid = 80
WinConsoleLogonSid = 81
WinThisOrganizationCertificateSid = 82
WinApplicationPackageAuthoritySid = 83
WinBuiltinAnyPackageSid = 84
WinCapabilityInternetClientSid = 85
WinCapabilityInternetClientServerSid = 86
WinCapabilityPrivateNetworkClientServerSid = 87
WinCapabilityPicturesLibrarySid = 88
WinCapabilityVideosLibrarySid = 89
WinCapabilityMusicLibrarySid = 90
WinCapabilityDocumentsLibrarySid = 91
WinCapabilitySharedUserCertificatesSid = 92
WinCapabilityEnterpriseAuthenticationSid = 93
WinCapabilityRemovableStorageSid = 94
WinBuiltinRDSRemoteAccessServersSid = 95
WinBuiltinRDSEndpointServersSid = 96
WinBuiltinRDSManagementServersSid = 97
WinUserModeDriversSid = 98
WinBuiltinHyperVAdminsSid = 99
WinAccountCloneableControllersSid = 100
WinBuiltinAccessControlAssistanceOperatorsSid = 101
WinBuiltinRemoteManagementUsersSid = 102
WinAuthenticationAuthorityAssertedSid = 103
WinAuthenticationServiceAssertedSid = 104
WinLocalAccountSid = 105
WinLocalAccountAndAdministratorSid = 106
WinAccountProtectedUsersSid = 107
WinCapabilityAppointmentsSid = 108
WinCapabilityContactsSid = 109
WinAccountDefaultSystemManagedSid = 110
WinBuiltinDefaultSystemManagedGroupSid = 111
WinBuiltinStorageReplicaAdminsSid = 112
WinAccountKeyAdminsSid = 113
WinAccountEnterpriseKeyAdminsSid = 114
WinAuthenticationKeyTrustSid = 115
WinAuthenticationKeyPropertyMFASid = 116
WinAuthenticationKeyPropertyAttestationSid = 117
WinAuthenticationFreshKeyAuthSid = 118
WinBuiltinDeviceOwnersSid = 119

class WELL_KNOWN_SID_TYPE(enum.IntFlag):
    WinNullSid = 0
    WinWorldSid = 1
    WinLocalSid = 2
    WinCreatorOwnerSid = 3
    WinCreatorGroupSid = 4
    WinCreatorOwnerServerSid = 5
    WinCreatorGroupServerSid = 6
    WinNtAuthoritySid = 7
    WinDialupSid = 8
    WinNetworkSid = 9
    WinBatchSid = 10
    WinInteractiveSid = 11
    WinServiceSid = 12
    WinAnonymousSid = 13
    WinProxySid = 14
    WinEnterpriseControllersSid = 15
    WinSelfSid = 16
    WinAuthenticatedUserSid = 17
    WinRestrictedCodeSid = 18
    WinTerminalServerSid = 19
    WinRemoteLogonIdSid = 20
    WinLogonIdsSid = 21
    WinLocalSystemSid = 22
    WinLocalServiceSid = 23
    WinNetworkServiceSid = 24
    WinBuiltinDomainSid = 25
    WinBuiltinAdministratorsSid = 26
    WinBuiltinUsersSid = 27
    WinBuiltinGuestsSid = 28
    WinBuiltinPowerUsersSid = 29
    WinBuiltinAccountOperatorsSid = 30
    WinBuiltinSystemOperatorsSid = 31
    WinBuiltinPrintOperatorsSid = 32
    WinBuiltinBackupOperatorsSid = 33
    WinBuiltinReplicatorSid = 34
    WinBuiltinPreWindows2000CompatibleAccessSid = 35
    WinBuiltinRemoteDesktopUsersSid = 36
    WinBuiltinNetworkConfigurationOperatorsSid = 37
    WinAccountAdministratorSid = 38
    WinAccountGuestSid = 39
    WinAccountKrbtgtSid = 40
    WinAccountDomainAdminsSid = 41
    WinAccountDomainUsersSid = 42
    WinAccountDomainGuestsSid = 43
    WinAccountComputersSid = 44
    WinAccountControllersSid = 45
    WinAccountCertAdminsSid = 46
    WinAccountSchemaAdminsSid = 47
    WinAccountEnterpriseAdminsSid = 48
    WinAccountPolicyAdminsSid = 49
    WinAccountRasAndIasServersSid = 50
    WinNTLMAuthenticationSid = 51
    WinDigestAuthenticationSid = 52
    WinSChannelAuthenticationSid = 53
    WinThisOrganizationSid = 54
    WinOtherOrganizationSid = 55
    WinBuiltinIncomingForestTrustBuildersSid = 56
    WinBuiltinPerfMonitoringUsersSid = 57
    WinBuiltinPerfLoggingUsersSid = 58
    WinBuiltinAuthorizationAccessSid = 59
    WinBuiltinTerminalServerLicenseServersSid = 60
    WinBuiltinDCOMUsersSid = 61
    WinBuiltinIUsersSid = 62
    WinIUserSid = 63
    WinBuiltinCryptoOperatorsSid = 64
    WinUntrustedLabelSid = 65
    WinLowLabelSid = 66 
    WinMediumLabelSid = 67
    WinHighLabelSid = 68
    WinSystemLabelSid = 69 
    WinWriteRestrictedCodeSid = 70
    WinCreatorOwnerRightsSid = 71
    WinCacheablePrincipalsGroupSid = 72
    WinNonCacheablePrincipalsGroupSid = 73
    WinEnterpriseReadonlyControllersSid = 74
    WinAccountReadonlyControllersSid = 75
    WinBuiltinEventLogReadersGroup = 76
    WinNewEnterpriseReadonlyControllersSid = 77
    WinBuiltinCertSvcDComAccessGroup = 78
    WinMediumPlusLabelSid = 79
    WinLocalLogonSid = 80
    WinConsoleLogonSid = 81
    WinThisOrganizationCertificateSid = 82
    WinApplicationPackageAuthoritySid = 83
    WinBuiltinAnyPackageSid = 84
    WinCapabilityInternetClientSid = 85
    WinCapabilityInternetClientServerSid = 86
    WinCapabilityPrivateNetworkClientServerSid = 87
    WinCapabilityPicturesLibrarySid = 88
    WinCapabilityVideosLibrarySid = 89
    WinCapabilityMusicLibrarySid = 90
    WinCapabilityDocumentsLibrarySid = 91
    WinCapabilitySharedUserCertificatesSid = 92
    WinCapabilityEnterpriseAuthenticationSid = 93
    WinCapabilityRemovableStorageSid = 94
    WinBuiltinRDSRemoteAccessServersSid = 95
    WinBuiltinRDSEndpointServersSid = 96
    WinBuiltinRDSManagementServersSid = 97
    WinUserModeDriversSid = 98
    WinBuiltinHyperVAdminsSid = 99
    WinAccountCloneableControllersSid = 100
    WinBuiltinAccessControlAssistanceOperatorsSid = 101
    WinBuiltinRemoteManagementUsersSid = 102
    WinAuthenticationAuthorityAssertedSid = 103
    WinAuthenticationServiceAssertedSid = 104
    WinLocalAccountSid = 105
    WinLocalAccountAndAdministratorSid = 106
    WinAccountProtectedUsersSid = 107
    WinCapabilityAppointmentsSid = 108
    WinCapabilityContactsSid = 109
    WinAccountDefaultSystemManagedSid = 110
    WinBuiltinDefaultSystemManagedGroupSid = 111
    WinBuiltinStorageReplicaAdminsSid = 112
    WinAccountKeyAdminsSid = 113
    WinAccountEnterpriseKeyAdminsSid = 114
    WinAuthenticationKeyTrustSid = 115
    WinAuthenticationKeyPropertyMFASid = 116
    WinAuthenticationKeyPropertyAttestationSid = 117
    WinAuthenticationFreshKeyAuthSid = 118
    WinBuiltinDeviceOwnersSid = 119


SYSTEM_LUID = (0x3e7, 0x0)
ANONYMOUS_LOGON_LUID = (0x3e6, 0x0)
LOCALSERVICE_LUID = (0x3e5, 0x0)
NETWORKSERVICE_LUID = (0x3e4, 0x0)
IUSER_LUID = (0x3e3, 0x0)
PROTECTED_TO_SYSTEM_LUID = (0x3e2, 0x0)

SE_GROUP_MANDATORY = 0x00000001
SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
SE_GROUP_ENABLED = 0x00000004
SE_GROUP_OWNER = 0x00000008
SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010
SE_GROUP_INTEGRITY = 0x00000020
SE_GROUP_INTEGRITY_ENABLED = 0x00000040
SE_GROUP_LOGON_ID = 0xC0000000
SE_GROUP_RESOURCE = 0x20000000

SE_GROUP_VALID_ATTRIBUTES  = (SE_GROUP_MANDATORY | 
                              SE_GROUP_ENABLED_BY_DEFAULT | 
                              SE_GROUP_ENABLED | 
                              SE_GROUP_OWNER | 
                              SE_GROUP_USE_FOR_DENY_ONLY | 
                              SE_GROUP_LOGON_ID | 
                              SE_GROUP_RESOURCE | 
                              SE_GROUP_INTEGRITY | 
                              SE_GROUP_INTEGRITY_ENABLED
)

ACL_REVISION = 2
ACL_REVISION_DS = 4

ACL_REVISION1 = 1
ACL_REVISION2 = 2
MIN_ACL_REVISION = ACL_REVISION2 
ACL_REVISION3 = 3
ACL_REVISION4 = 4
MAX_ACL_REVISION = ACL_REVISION4

class _ACL(Structure):
    _fields_ = [('AclRevision', BYTE),
                ('Sbz1', BYTE),
                ('AclSize', WORD),
                ('AceCount', WORD),
                ('Sbz2', WORD)
    ]

ACL = _ACL
PACL = POINTER(ACL)

class _ACE_HEADER(Structure):
    _fields_ = [('AceType', BYTE),
                ('AceFlags', BYTE),
                ('AceSize', WORD)
    ]

ACE_HEADER = _ACE_HEADER
PACE_HEADER = POINTER(ACE_HEADER)

ACCESS_MIN_MS_ACE_TYPE = 0x0
ACCESS_ALLOWED_ACE_TYPE = 0x0
ACCESS_DENIED_ACE_TYPE = 0x1
SYSTEM_AUDIT_ACE_TYPE = 0x2
SYSTEM_ALARM_ACE_TYPE = 0x3
ACCESS_MAX_MS_V2_ACE_TYPE = 0x3

ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x4
ACCESS_MAX_MS_V3_ACE_TYPE = 0x4

ACCESS_MIN_MS_OBJECT_ACE_TYPE = 0x5
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x5
ACCESS_DENIED_OBJECT_ACE_TYPE = 0x6
SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x7
SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x8
ACCESS_MAX_MS_OBJECT_ACE_TYPE = 0x8

ACCESS_MAX_MS_V4_ACE_TYPE = 0x8
ACCESS_MAX_MS_ACE_TYPE = 0x8

ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x9
ACCESS_DENIED_CALLBACK_ACE_TYPE = 0xA
ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xB
ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0xC
SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0xD
SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0xE
SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0xF
SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10

SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13
SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE = 0x14
SYSTEM_ACCESS_FILTER_ACE_TYPE = 0x15
ACCESS_MAX_MS_V5_ACE_TYPE = 0x15

OBJECT_INHERIT_ACE = 0x1
CONTAINER_INHERIT_ACE = 0x2
NO_PROPAGATE_INHERIT_ACE = 0x4
INHERIT_ONLY_ACE = 0x8
INHERITED_ACE = 0x10
VALID_INHERIT_FLAGS = 0x1F
CRITICAL_ACE_FLAG = 0x20

SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
FAILED_ACCESS_ACE_FLAG = 0x80
TRUST_PROTECTED_FILTER_ACE_FLAG = 0x40

class _ACCESS_ALLOWED_ACE(Structure):
    _fields_ = [('Header', ACE_HEADER),
                ('Mask', ACCESS_MASK),
                ('SidStart', DWORD)
    ]

ACCESS_ALLOWED_ACE = _ACCESS_ALLOWED_ACE
PACCESS_ALLOWED_ACE = POINTER(ACCESS_ALLOWED_ACE)

ACCESS_DENIED_ACE = ACCESS_ALLOWED_ACE
PACCESS_DENIED_ACE = PACCESS_ALLOWED_ACE

SYSTEM_AUDIT_ACE = ACCESS_ALLOWED_ACE
PSYSTEM_AUDIT_ACE = PACCESS_ALLOWED_ACE

SYSTEM_ALARM_ACE = ACCESS_ALLOWED_ACE
PSYSTEM_ALARM_ACE = PACCESS_ALLOWED_ACE

SYSTEM_RESOURCE_ATTRIBUTE_ACE = ACCESS_ALLOWED_ACE
PSYSTEM_RESOURCE_ATTRIBUTE_ACE = PACCESS_ALLOWED_ACE

SYSTEM_SCOPED_POLICY_ID_ACE = ACCESS_ALLOWED_ACE
PSYSTEM_SCOPED_POLICY_ID_ACE = PACCESS_ALLOWED_ACE

SYSTEM_MANDATORY_LABEL_ACE = ACCESS_ALLOWED_ACE
PSYSTEM_MANDATORY_LABEL_ACE = PACCESS_ALLOWED_ACE

SYSTEM_PROCESS_TRUST_LABEL_ACE = ACCESS_ALLOWED_ACE
PSYSTEM_PROCESS_TRUST_LABEL_ACE = PACCESS_ALLOWED_ACE

SYSTEM_ACCESS_FILTER_ACE = ACCESS_ALLOWED_ACE
PSYSTEM_ACCESS_FILTER_ACE = PACCESS_ALLOWED_ACE

SYSTEM_MANDATORY_LABEL_NO_WRITE_UP = 0x1
SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0x2
SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP = 0x4

SYSTEM_MANDATORY_LABEL_VALID_MASK = (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | 
                                     SYSTEM_MANDATORY_LABEL_NO_READ_UP | 
                                     SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
)

SYSTEM_PROCESS_TRUST_LABEL_VALID_MASK = 0x00ffffff
SYSTEM_PROCESS_TRUST_NOCONSTRAINT_MASK = 0xffffffff
SYSTEM_ACCESS_FILTER_VALID_MASK = 0x00ffffff
SYSTEM_ACCESS_FILTER_NOCONSTRAINT_MASK = 0xffffffff

class _ACCESS_ALLOWED_OBJECT_ACE(Structure):
    _fields_ = [('Header', ACE_HEADER),
                ('Mask', ACCESS_MASK),
                ('Flags', DWORD),
                ('ObjectType', GUID),
                ('InheritedObjectType', GUID),
                ('SidStart', DWORD)
    ]

ACCESS_ALLOWED_OBJECT_ACE = _ACCESS_ALLOWED_OBJECT_ACE
PACCESS_ALLOWED_OBJECT_ACE = POINTER(ACCESS_ALLOWED_OBJECT_ACE)

ACCESS_DENIED_OBJECT_ACE = ACCESS_ALLOWED_OBJECT_ACE
PACCESS_DENIED_OBJECT_ACE = PACCESS_ALLOWED_OBJECT_ACE

SYSTEM_AUDIT_OBJECT_ACE = ACCESS_ALLOWED_OBJECT_ACE
PSYSTEM_AUDIT_OBJECT_ACE = PACCESS_ALLOWED_OBJECT_ACE

SYSTEM_ALARM_OBJECT_ACE = ACCESS_ALLOWED_OBJECT_ACE
PSYSTEM_ALARM_OBJECT_ACE = PACCESS_ALLOWED_OBJECT_ACE

class _ACCESS_ALLOWED_CALLBACK_ACE(Structure):
    _fields_ = [('Header', ACE_HEADER),
                ('Mask', ACCESS_MASK),
                ('SidStart', DWORD)
    ]

ACCESS_ALLOWED_CALLBACK_ACE = _ACCESS_ALLOWED_CALLBACK_ACE
PACCESS_ALLOWED_CALLBACK_ACE = POINTER(ACCESS_ALLOWED_CALLBACK_ACE)

ACCESS_DENIED_CALLBACK_ACE = ACCESS_ALLOWED_CALLBACK_ACE
PACCESS_DENIED_CALLBACK_ACE = PACCESS_ALLOWED_CALLBACK_ACE

SYSTEM_AUDIT_CALLBACK_ACE = ACCESS_ALLOWED_CALLBACK_ACE
PSYSTEM_AUDIT_CALLBACK_ACE = PACCESS_ALLOWED_CALLBACK_ACE

SYSTEM_ALARM_CALLBACK_ACE = ACCESS_ALLOWED_CALLBACK_ACE
PSYSTEM_ALARM_CALLBACK_ACE = PACCESS_ALLOWED_CALLBACK_ACE

ACCESS_ALLOWED_CALLBACK_OBJECT_ACE = ACCESS_ALLOWED_OBJECT_ACE
PACCESS_ALLOWED_CALLBACK_OBJECT_ACE = PACCESS_ALLOWED_OBJECT_ACE

ACCESS_DENIED_CALLBACK_OBJECT_ACE = ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
PACCESS_DENIED_CALLBACK_OBJECT_ACE = PACCESS_ALLOWED_CALLBACK_OBJECT_ACE

SYSTEM_AUDIT_CALLBACK_OBJECT_ACE = ACCESS_ALLOWED_OBJECT_ACE
PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE = PACCESS_ALLOWED_OBJECT_ACE

SYSTEM_ALARM_CALLBACK_OBJECT_ACE = ACCESS_ALLOWED_OBJECT_ACE
PSYSTEM_ALARM_CALLBACK_OBJECT_ACE = PACCESS_ALLOWED_OBJECT_ACE

ACE_OBJECT_TYPE_PRESENT = 0x1
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2

AclRevisionInformation = 1
AclSizeInformation = 2

class _ACL_INFORMATION_CLASS(enum.IntFlag):
    AclRevisionInformation = 1
    AclSizeInformation = 2

ACL_INFORMATION_CLASS = _ACL_INFORMATION_CLASS

class _ACL_REVISION_INFORMATION(Structure):
    _fields_ = [('AclRevision', DWORD)]

ACL_REVISION_INFORMATION = _ACL_REVISION_INFORMATION
PACL_REVISION_INFORMATION = POINTER(ACL_REVISION_INFORMATION)

class _ACL_SIZE_INFORMATION(Structure):
    _fields_ = [('AceCount', DWORD),
                ('AclBytesInUse', DWORD),
                ('AclBytesFree', DWORD),
    ]

ACL_SIZE_INFORMATION = _ACL_SIZE_INFORMATION
PACL_SIZE_INFORMATION = POINTER(ACL_SIZE_INFORMATION)

SECURITY_DESCRIPTOR_REVISION = 1
SECURITY_DESCRIPTOR_REVISION1 = 1

SECURITY_DESCRIPTOR_CONTROL = WORD
PSECURITY_DESCRIPTOR_CONTROL = PWORD

class _SECURITY_DESCRIPTOR_RELATIVE(Structure):
    _fields_ = [('Revision', BYTE),
                ('Sbz1', BYTE),
                ('Control', SECURITY_DESCRIPTOR_CONTROL),
                ('Owner', DWORD),
                ('Group', DWORD),
                ('Sacl', DWORD),
                ('Dacl', DWORD)
    ]

SECURITY_DESCRIPTOR_RELATIVE = _SECURITY_DESCRIPTOR_RELATIVE
PSECURITY_DESCRIPTOR_RELATIVE = POINTER(SECURITY_DESCRIPTOR_RELATIVE)

SECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR_RELATIVE
PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR_RELATIVE

class _SECURITY_OBJECT_AI_PARAMS(Structure):
    _fields_ = [('Size', DWORD),
                ('ConstraintMask', DWORD)
    ]

SECURITY_OBJECT_AI_PARAMS = _SECURITY_OBJECT_AI_PARAMS
PSECURITY_OBJECT_AI_PARAMS = POINTER(SECURITY_OBJECT_AI_PARAMS)

class _OBJECT_TYPE_LIST(Structure):
    _fields_ = [('Level', WORD),
                ('Sbz', WORD),
                ('ObjectType', POINTER(GUID))
    ]

OBJECT_TYPE_LIST = _OBJECT_TYPE_LIST
POBJECT_TYPE_LIST = POINTER(OBJECT_TYPE_LIST)

SECURITY_DESCRIPTOR_MIN_LENGTH = sizeof(SECURITY_DESCRIPTOR())

SE_OWNER_DEFAULTED = 0x0001
SE_GROUP_DEFAULTED = 0x0002
SE_DACL_PRESENT = 0x0004
SE_DACL_DEFAULTED = 0x0008
SE_SACL_PRESENT = 0x0010
SE_SACL_DEFAULTED = 0x0020
SE_DACL_AUTO_INHERIT_REQ = 0x0100
SE_SACL_AUTO_INHERIT_REQ = 0x0200
SE_DACL_AUTO_INHERITED = 0x0400
SE_SACL_AUTO_INHERITED = 0x0800
SE_DACL_PROTECTED = 0x1000
SE_SACL_PROTECTED = 0x2000
SE_RM_CONTROL_VALID = 0x4000
SE_SELF_RELATIVE = 0x8000

ACCESS_OBJECT_GUID = 0
ACCESS_PROPERTY_SET_GUID = 1
ACCESS_PROPERTY_GUID = 2

ACCESS_MAX_LEVEL = 4

AuditEventObjectAccess = 0
AuditEventDirectoryServiceAccess = 1

class _AUDIT_EVENT_TYPE(enum.IntFlag):
    AuditEventObjectAccess = 0
    AuditEventDirectoryServiceAccess = 1

AUDIT_EVENT_TYPE = _AUDIT_EVENT_TYPE
PAUDIT_EVENT_TYPE = AUDIT_EVENT_TYPE

AUDIT_ALLOW_NO_PRIVILEGE = 0x1

ACCESS_DS_SOURCE_A = b"DS"
ACCESS_DS_SOURCE_W = "DS"
ACCESS_DS_OBJECT_TYPE_NAME_A = b"Directory Service Object"
ACCESS_DS_OBJECT_TYPE_NAME_W = "Directory Service Object"

SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_REMOVED = 0X00000004
SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000

SE_PRIVILEGE_VALID_ATTRIBUTES = (SE_PRIVILEGE_ENABLED_BY_DEFAULT | 
                                 SE_PRIVILEGE_ENABLED | 
                                 SE_PRIVILEGE_REMOVED | 
                                 SE_PRIVILEGE_USED_FOR_ACCESS
)

PRIVILEGE_SET_ALL_NECESSARY = 1

class _PRIVILEGE_SET(Structure):
    _fields_ = [('PrivilegeCount', DWORD),
                ('Control', DWORD),
                ('Privilege', LUID_AND_ATTRIBUTES * ANYSIZE_ARRAY),
    ]

PRIVILEGE_SET = _PRIVILEGE_SET
PPRIVILEGE_SET = POINTER(PRIVILEGE_SET)

ACCESS_REASON_TYPE_MASK = 0x00ff0000
ACCESS_REASON_DATA_MASK = 0x0000ffff

ACCESS_REASON_STAGING_MASK = 0x80000000
ACCESS_REASON_EXDATA_MASK = 0x7f000000

AccessReasonNone = 0x00000000
AccessReasonAllowedAce = 0x00010000
AccessReasonDeniedAce = 0x00020000
AccessReasonAllowedParentAce = 0x00030000
AccessReasonDeniedParentAce = 0x00040000
AccessReasonNotGrantedByCape = 0x00050000
AccessReasonNotGrantedByParentCape = 0x00060000
AccessReasonNotGrantedToAppContainer = 0x00070000
AccessReasonMissingPrivilege = 0x00100000
AccessReasonFromPrivilege = 0x00200000
AccessReasonIntegrityLevel = 0x00300000
AccessReasonOwnership = 0x00400000
AccessReasonNullDacl = 0x00500000
AccessReasonEmptyDacl = 0x00600000
AccessReasonNoSD = 0x00700000
AccessReasonNoGrant = 0x00800000
AccessReasonTrustLabel = 0x00900000
AccessReasonFilterAce = 0x00a00000

class _ACCESS_REASON_TYPE(enum.IntFlag):
    AccessReasonNone = 0x00000000
    AccessReasonAllowedAce = 0x00010000
    AccessReasonDeniedAce = 0x00020000
    AccessReasonAllowedParentAce = 0x00030000
    AccessReasonDeniedParentAce = 0x00040000
    AccessReasonNotGrantedByCape = 0x00050000
    AccessReasonNotGrantedByParentCape = 0x00060000
    AccessReasonNotGrantedToAppContainer = 0x00070000
    AccessReasonMissingPrivilege = 0x00100000
    AccessReasonFromPrivilege = 0x00200000
    AccessReasonIntegrityLevel = 0x00300000
    AccessReasonOwnership = 0x00400000
    AccessReasonNullDacl = 0x00500000
    AccessReasonEmptyDacl = 0x00600000
    AccessReasonNoSD = 0x00700000
    AccessReasonNoGrant = 0x00800000
    AccessReasonTrustLabel = 0x00900000
    AccessReasonFilterAce = 0x00a00000

ACCESS_REASON_TYPE = _ACCESS_REASON_TYPE

ACCESS_REASON = DWORD

class _ACCESS_REASONS(Structure):
    _fields_ = [('Data', ACCESS_REASON * 32)]

ACCESS_REASONS = _ACCESS_REASONS
PACCESS_REASONS = POINTER(ACCESS_REASONS)

SE_SECURITY_DESCRIPTOR_FLAG_NO_OWNER_ACE = 0x00000001
SE_SECURITY_DESCRIPTOR_FLAG_NO_LABEL_ACE = 0x00000002
SE_SECURITY_DESCRIPTOR_FLAG_NO_ACCESS_FILTER_ACE = 0x00000004
SE_SECURITY_DESCRIPTOR_VALID_FLAGS = 0x00000007

SE_ACCESS_CHECK_FLAG_NO_LEARNING_MODE_LOGGING = 0x00000008
SE_ACCESS_CHECK_VALID_FLAGS = 0x00000008

class _SE_SECURITY_DESCRIPTOR(Structure):
    _fields_ = [('Size', DWORD),
                ('Flags', DWORD),
                ('SecurityDescriptor', PSECURITY_DESCRIPTOR)
    ]

SE_SECURITY_DESCRIPTOR = _SE_SECURITY_DESCRIPTOR
PSE_SECURITY_DESCRIPTOR = POINTER(SE_SECURITY_DESCRIPTOR)

class _SE_ACCESS_REQUEST(Structure):
    _fields_ = [('Size', DWORD),
                ('SeSecurityDescriptor', PSE_SECURITY_DESCRIPTOR),
                ('DesiredAccess', ACCESS_MASK),
                ('PreviouslyGrantedAccess', ACCESS_MASK),
                ('PrincipalSelfSid', PSID),
                ('GenericMapping', PGENERIC_MAPPING),
                ('ObjectTypeListCount', DWORD),
                ('ObjectTypeList', POBJECT_TYPE_LIST)
    ]

SE_ACCESS_REQUEST = _SE_ACCESS_REQUEST
PSE_ACCESS_REQUEST = POINTER(SE_ACCESS_REQUEST)

class _SE_ACCESS_REPLY(Structure):
    _fields_ = [('Size', DWORD),
                ('ResultListCount', DWORD),
                ('GrantedAccess', PACCESS_MASK),
                ('AccessStatus', PDWORD),
                ('AccessReason', PACCESS_REASONS),
                ('Privileges', PPRIVILEGE_SET)
    ]

SE_ACCESS_REPLY = _SE_ACCESS_REPLY
PSE_ACCESS_REPLY = POINTER(SE_ACCESS_REPLY)

SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege"
SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege"
SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege"
SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege"
SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege"
SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege"
SE_TCB_NAME = "SeTcbPrivilege"
SE_SECURITY_NAME = "SeSecurityPrivilege"
SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege"
SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege"
SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege"
SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege"
SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege"
SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege"
SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege"
SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege"
SE_BACKUP_NAME = "SeBackupPrivilege"
SE_RESTORE_NAME = "SeRestorePrivilege"
SE_SHUTDOWN_NAME = "SeShutdownPrivilege"
SE_DEBUG_NAME = "SeDebugPrivilege"
SE_AUDIT_NAME = "SeAuditPrivilege"
SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege"
SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege"
SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege"
SE_UNDOCK_NAME = "SeUndockPrivilege"
SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege"
SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege"
SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege"
SE_IMPERSONATE_NAME = "SeImpersonatePrivilege"
SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege"
SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege"
SE_RELABEL_NAME = "SeRelabelPrivilege"
SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege"
SE_TIME_ZONE_NAME = "SeTimeZonePrivilege"
SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege"
SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME = "SeDelegateSessionUserImpersonatePrivilege"

SE_ACTIVATE_AS_USER_CAPABILITY = "activateAsUser"
SE_CONSTRAINED_IMPERSONATION_CAPABILITY = "constrainedImpersonation"
SE_SESSION_IMPERSONATION_CAPABILITY = "sessionImpersonation"
SE_MUMA_CAPABILITY = "muma"
SE_DEVELOPMENT_MODE_NETWORK_CAPABILITY = "developmentModeNetwork"
SE_LEARNING_MODE_LOGGING_CAPABILITY = "learningModeLogging"
SE_PERMISSIVE_LEARNING_MODE_CAPABILITY = "permissiveLearningMode"
SE_APP_SILO_VOLUME_ROOT_MINIMAL_CAPABILITY = "isolatedWin32-volumeRootMinimal"
SE_APP_SILO_PROFILES_ROOT_MINIMAL_CAPABILITY = "isolatedWin32-profilesRootMinimal"
SE_APP_SILO_USER_PROFILE_MINIMAL_CAPABILITY = "isolatedWin32-userProfileMinimal"
SE_APP_SILO_PRINT_CAPABILITY = "isolatedWin32-print"

SecurityAnonymous = 0
SecurityIdentification = 1
SecurityImpersonation = 2
SecurityDelegation = 3

class _SECURITY_IMPERSONATION_LEVEL(enum.IntFlag):
    SecurityAnonymous = 0
    SecurityIdentification = 1
    SecurityImpersonation = 2
    SecurityDelegation = 3

SECURITY_IMPERSONATION_LEVEL = _SECURITY_IMPERSONATION_LEVEL
PSECURITY_IMPERSONATION_LEVEL = SECURITY_IMPERSONATION_LEVEL

SECURITY_MAX_IMPERSONATION_LEVEL = SecurityDelegation
SECURITY_MIN_IMPERSONATION_LEVEL = SecurityAnonymous
DEFAULT_IMPERSONATION_LEVEL = SecurityImpersonation


def VALID_IMPERSONATION_LEVEL(L: int | float) -> bool:
    return (L >= SECURITY_MIN_IMPERSONATION_LEVEL) and (L <= SECURITY_MAX_IMPERSONATION_LEVEL)


TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100

TOKEN_ALL_ACCESS_P = (STANDARD_RIGHTS_REQUIRED | 
                      TOKEN_ASSIGN_PRIMARY | 
                      TOKEN_DUPLICATE | 
                      TOKEN_IMPERSONATE | 
                      TOKEN_QUERY | 
                      TOKEN_QUERY_SOURCE | 
                      TOKEN_ADJUST_PRIVILEGES | 
                      TOKEN_ADJUST_GROUPS | 
                      TOKEN_ADJUST_DEFAULT
)

TOKEN_ALL_ACCESS = (TOKEN_ALL_ACCESS_P | TOKEN_ADJUST_SESSIONID)
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)

TOKEN_WRITE  =(STANDARD_RIGHTS_WRITE | 
               TOKEN_ADJUST_PRIVILEGES | 
               TOKEN_ADJUST_GROUPS | 
               TOKEN_ADJUST_DEFAULT
)

TOKEN_EXECUTE = STANDARD_RIGHTS_EXECUTE

TOKEN_TRUST_CONSTRAINT_MASK = (STANDARD_RIGHTS_READ | 
                               TOKEN_QUERY | 
                               TOKEN_QUERY_SOURCE
)

if NTDDI_VERSION >= NTDDI_WIN8:
    TOKEN_ACCESS_PSEUDO_HANDLE_WIN8 = (TOKEN_QUERY | TOKEN_QUERY_SOURCE)
    TOKEN_ACCESS_PSEUDO_HANDLE = TOKEN_ACCESS_PSEUDO_HANDLE_WIN8

TokenPrimary = 1
TokenImpersonation = 2

class _TOKEN_TYPE(enum.IntFlag):
    TokenPrimary = 1
    TokenImpersonation = 2

TOKEN_TYPE = _TOKEN_TYPE
PTOKEN_TYPE = _TOKEN_TYPE

TokenElevationTypeDefault = 1
TokenElevationTypeFull = 2
TokenElevationTypeLimited = 3

class _TOKEN_ELEVATION_TYPE(enum.IntFlag):
    TokenElevationTypeDefault = 1
    TokenElevationTypeFull = 2
    TokenElevationTypeLimited = 3

TOKEN_ELEVATION_TYPE = _TOKEN_ELEVATION_TYPE
PTOKEN_ELEVATION_TYPE = TOKEN_ELEVATION_TYPE

TokenUser = 1
TokenGroups = 2
TokenPrivileges = 3
TokenOwner = 4
TokenPrimaryGroup = 5
TokenDefaultDacl = 6
TokenSource = 7
TokenType = 8
TokenImpersonationLevel = 9
TokenStatistics = 10
TokenRestrictedSids = 11
TokenSessionId = 12
TokenGroupsAndPrivileges = 13
TokenSessionReference = 14
TokenSandBoxInert = 15
TokenAuditPolicy = 16
TokenOrigin = 17
TokenElevationType = 18
TokenLinkedToken = 19
TokenElevation = 20
TokenHasRestrictions = 21
TokenAccessInformation = 22
TokenVirtualizationAllowed = 23
TokenVirtualizationEnabled = 24
TokenIntegrityLevel = 25
TokenUIAccess = 26
TokenMandatoryPolicy = 27
TokenLogonSid = 28
TokenIsAppContainer = 29
TokenCapabilities = 30
TokenAppContainerSid = 31
TokenAppContainerNumber = 32
TokenUserClaimAttributes = 33
TokenDeviceClaimAttributes = 34
TokenRestrictedUserClaimAttributes = 35
TokenRestrictedDeviceClaimAttributes = 36
TokenDeviceGroups = 37
TokenRestrictedDeviceGroups = 38
TokenSecurityAttributes = 39
TokenIsRestricted = 40
TokenProcessTrustLevel = 41
TokenPrivateNameSpace = 42
TokenSingletonAttributes = 43
TokenBnoIsolation = 44
TokenChildProcessFlags = 45
TokenIsLessPrivilegedAppContainer = 46
TokenIsSandboxed = 47
TokenIsAppSilo = 48
MaxTokenInfoClass = 49

class _TOKEN_INFORMATION_CLASS(enum.IntFlag):
    TokenUser = 1
    TokenGroups = 2
    TokenPrivileges = 3
    TokenOwner = 4
    TokenPrimaryGroup = 5
    TokenDefaultDacl = 6
    TokenSource = 7
    TokenType = 8
    TokenImpersonationLevel = 9
    TokenStatistics = 10
    TokenRestrictedSids = 11
    TokenSessionId = 12
    TokenGroupsAndPrivileges = 13
    TokenSessionReference = 14
    TokenSandBoxInert = 15
    TokenAuditPolicy = 16
    TokenOrigin = 17
    TokenElevationType = 18
    TokenLinkedToken = 19
    TokenElevation = 20
    TokenHasRestrictions = 21
    TokenAccessInformation = 22
    TokenVirtualizationAllowed = 23
    TokenVirtualizationEnabled = 24
    TokenIntegrityLevel = 25
    TokenUIAccess = 26
    TokenMandatoryPolicy = 27
    TokenLogonSid = 28
    TokenIsAppContainer = 29
    TokenCapabilities = 30
    TokenAppContainerSid = 31
    TokenAppContainerNumber = 32
    TokenUserClaimAttributes = 33
    TokenDeviceClaimAttributes = 34
    TokenRestrictedUserClaimAttributes = 35
    TokenRestrictedDeviceClaimAttributes = 36
    TokenDeviceGroups = 37
    TokenRestrictedDeviceGroups = 38
    TokenSecurityAttributes = 39
    TokenIsRestricted = 40
    TokenProcessTrustLevel = 41
    TokenPrivateNameSpace = 42
    TokenSingletonAttributes = 43
    TokenBnoIsolation = 44
    TokenChildProcessFlags = 45
    TokenIsLessPrivilegedAppContainer = 46
    TokenIsSandboxed = 47
    TokenIsAppSilo = 48
    MaxTokenInfoClass = 49

TOKEN_INFORMATION_CLASS = _TOKEN_INFORMATION_CLASS
PTOKEN_INFORMATION_CLASS = TOKEN_INFORMATION_CLASS

class _TOKEN_USER(Structure):
    _fields_ = [('User', SID_AND_ATTRIBUTES)]

TOKEN_USER = _TOKEN_USER
PTOKEN_USER = POINTER(TOKEN_USER)

class _SE_TOKEN_USER(Structure):
    class UserUnion(Union):
        _fields_ = [('TokenUser', TOKEN_USER),
                    ('User', SID_AND_ATTRIBUTES)
        ]

    class SidBufferUnion(Union):
        _fields_ = [('Sid', SID),
                    ('Buffer', BYTE * SECURITY_MAX_SID_SIZE)
        ]

    _anonymous_ = ['UserUnion', 'SidBufferUnion']
    _fields_ = [('UserUnion', UserUnion),
                ('SidBufferUnion', SidBufferUnion)
    ]

SE_TOKEN_USER = _SE_TOKEN_USER
PSE_TOKEN_USER = POINTER(SE_TOKEN_USER)

TOKEN_USER_MAX_SIZE = sizeof(TOKEN_USER()) + SECURITY_MAX_SID_SIZE

class _TOKEN_GROUPS(Structure):
    _fields_ = [('GroupCount', DWORD)]
    _fields_.append(('Groups', SID_AND_ATTRIBUTES * ANYSIZE_ARRAY))

TOKEN_GROUPS = _TOKEN_GROUPS
PTOKEN_GROUPS = POINTER(TOKEN_GROUPS)

class _TOKEN_PRIVILEGES(Structure):
    _fields_ = [('PrivilegeCount', DWORD),
                ('Privileges', LUID_AND_ATTRIBUTES * ANYSIZE_ARRAY)
    ]

TOKEN_PRIVILEGES = _TOKEN_PRIVILEGES
PTOKEN_PRIVILEGES = POINTER(TOKEN_PRIVILEGES)

class _TOKEN_OWNER(Structure):
    _fields_ = [('Owner', PSID)]

TOKEN_OWNER = _TOKEN_OWNER
PTOKEN_OWNER = POINTER(TOKEN_OWNER)

TOKEN_OWNER_MAX_SIZE = sizeof(TOKEN_OWNER()) + SECURITY_MAX_SID_SIZE

class _TOKEN_PRIMARY_GROUP(Structure):
    _fields_ = [('PrimaryGroup', PSID)]

TOKEN_PRIMARY_GROUP = _TOKEN_PRIMARY_GROUP
PTOKEN_PRIMARY_GROUP = POINTER(TOKEN_PRIMARY_GROUP)

class _TOKEN_DEFAULT_DACL(Structure):
    _fields_ = [('DefaultDacl', PACL)]

TOKEN_DEFAULT_DACL = _TOKEN_DEFAULT_DACL
PTOKEN_DEFAULT_DACL = POINTER(TOKEN_DEFAULT_DACL)

class _TOKEN_USER_CLAIMS(Structure):
    _fields_ = [('UserClaims', PCLAIMS_BLOB)]

TOKEN_USER_CLAIMS = _TOKEN_USER_CLAIMS
PTOKEN_USER_CLAIMS = POINTER(TOKEN_USER_CLAIMS)

class _TOKEN_DEVICE_CLAIMS(Structure):
    _fields_ = [('DeviceClaims', PCLAIMS_BLOB)]

TOKEN_DEVICE_CLAIMS = _TOKEN_DEVICE_CLAIMS
PTOKEN_DEVICE_CLAIMS = POINTER(TOKEN_DEVICE_CLAIMS)

class _TOKEN_GROUPS_AND_PRIVILEGES(Structure):
    _fields_ = [('SidCount', DWORD),
                ('SidLength', DWORD),
                ('Sids', PSID_AND_ATTRIBUTES),
                ('RestrictedSidCount', DWORD),
                ('RestrictedSidLength', DWORD),
                ('RestrictedSids', PSID_AND_ATTRIBUTES),
                ('PrivilegeCount', DWORD),
                ('PrivilegeLength', DWORD),
                ('Privileges', PLUID_AND_ATTRIBUTES),
                ('AuthenticationId', LUID)
    ]

TOKEN_GROUPS_AND_PRIVILEGES = _TOKEN_GROUPS_AND_PRIVILEGES
PTOKEN_GROUPS_AND_PRIVILEGES = POINTER(TOKEN_GROUPS_AND_PRIVILEGES)

class _TOKEN_LINKED_TOKEN(Structure):
    _fields_ = [('LinkedToken', HANDLE)]

TOKEN_LINKED_TOKEN = _TOKEN_LINKED_TOKEN
PTOKEN_LINKED_TOKEN = POINTER(TOKEN_LINKED_TOKEN)

class _TOKEN_ELEVATION(Structure):
    _fields_ = [('TokenIsElevated', DWORD)]

TOKEN_ELEVATION = _TOKEN_ELEVATION
PTOKEN_ELEVATION = POINTER(TOKEN_ELEVATION)

class _TOKEN_MANDATORY_LABEL(Structure):
    _fields_ = [('Label', SID_AND_ATTRIBUTES)]

TOKEN_MANDATORY_LABEL = _TOKEN_MANDATORY_LABEL
PTOKEN_MANDATORY_LABEL = POINTER(TOKEN_MANDATORY_LABEL)

TOKEN_MANDATORY_POLICY_OFF = 0x0
TOKEN_MANDATORY_POLICY_NO_WRITE_UP = 0x1
TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN = 0x2

TOKEN_MANDATORY_POLICY_VALID_MASK = (TOKEN_MANDATORY_POLICY_NO_WRITE_UP | 
                                     TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN
)

TOKEN_INTEGRITY_LEVEL_MAX_SIZE = ((DWORD(sizeof(TOKEN_MANDATORY_LABEL())).value + sizeof(PVOID()) - 1) & ~(sizeof(PVOID())-1)) + SECURITY_MAX_SID_SIZE

class _TOKEN_MANDATORY_POLICY(Structure):
    _fields_ = [('Policy', DWORD)]

TOKEN_MANDATORY_POLICY = _TOKEN_MANDATORY_POLICY
PTOKEN_MANDATORY_POLICY = POINTER(TOKEN_MANDATORY_POLICY)

PSECURITY_ATTRIBUTES_OPAQUE = PVOID

class _TOKEN_ACCESS_INFORMATION(Structure):
    _fields_ = [('SidHash', PSID_AND_ATTRIBUTES_HASH),
                ('RestrictedSidHash', PSID_AND_ATTRIBUTES_HASH),
                ('Privileges', PTOKEN_PRIVILEGES),
                ('AuthenticationId', LUID),
                ('TokenType', UINT),
                ('ImpersonationLevel', UINT),
                ('MandatoryPolicy', TOKEN_MANDATORY_POLICY),
                ('Flags', DWORD),
                ('AppContainerNumber', DWORD),
                ('PackageSid', PSID),
                ('CapabilitiesHash', PSID_AND_ATTRIBUTES_HASH)
    ]

TOKEN_ACCESS_INFORMATION = _TOKEN_ACCESS_INFORMATION
PTOKEN_ACCESS_INFORMATION = POINTER(TOKEN_ACCESS_INFORMATION)

POLICY_AUDIT_SUBCATEGORY_COUNT = 56

class _TOKEN_AUDIT_POLICY(Structure):
    _fields_ = [('PerUserPolicy', UCHAR * ((POLICY_AUDIT_SUBCATEGORY_COUNT >> 1) + 1))]

TOKEN_AUDIT_POLICY = _TOKEN_AUDIT_POLICY
PTOKEN_AUDIT_POLICY = POINTER(TOKEN_AUDIT_POLICY)

TOKEN_SOURCE_LENGTH = 8

class _TOKEN_SOURCE(Structure):
    _fields_ = [('SourceName', CHAR * TOKEN_SOURCE_LENGTH),
                ('SourceIdentifier', LUID)
    ]

TOKEN_SOURCE = _TOKEN_SOURCE
PTOKEN_SOURCE = POINTER(TOKEN_SOURCE)

class _TOKEN_STATISTICS(Structure):
    _fields_ = [('TokenId', LUID),
                ('AuthenticationId', LUID),
                ('ExpirationTime', LARGE_INTEGER),
                ('TokenType', UINT),
                ('ImpersonationLevel', UINT),
                ('DynamicCharged', DWORD),
                ('DynamicAvailable', DWORD),
                ('GroupCount', DWORD),
                ('PrivilegeCount', DWORD),
                ('ModifiedId', LUID)
    ]

TOKEN_STATISTICS = _TOKEN_STATISTICS
PTOKEN_STATISTICS = POINTER(TOKEN_STATISTICS)

class _TOKEN_CONTROL(Structure):
    _fields_ = [('TokenId', LUID),
                ('AuthenticationId', LUID),
                ('ModifiedId', LUID),
                ('TokenSource', TOKEN_SOURCE)
    ]

TOKEN_CONTROL = _TOKEN_CONTROL
PTOKEN_CONTROL = POINTER(TOKEN_CONTROL)

class _TOKEN_ORIGIN(Structure):
    _fields_ = [('OriginatingLogonSession', LUID)]

TOKEN_ORIGIN = _TOKEN_ORIGIN
PTOKEN_ORIGIN = POINTER(TOKEN_ORIGIN)

MandatoryLevelUntrusted = 0
MandatoryLevelLow = 1
MandatoryLevelMedium = 2
MandatoryLevelHigh = 3
MandatoryLevelSystem = 4
MandatoryLevelSecureProcess = 5
MandatoryLevelCount = 6

class _MANDATORY_LEVEL(enum.IntFlag):
    MandatoryLevelUntrusted = 0
    MandatoryLevelLow = 1
    MandatoryLevelMedium = 2
    MandatoryLevelHigh = 3
    MandatoryLevelSystem = 4
    MandatoryLevelSecureProcess = 5
    MandatoryLevelCount = 6

MANDATORY_LEVEL = _MANDATORY_LEVEL
PMANDATORY_LEVEL = MANDATORY_LEVEL

class _TOKEN_APPCONTAINER_INFORMATION(Structure):
    _fields_ = [('TokenAppContainer', PSID)]

TOKEN_APPCONTAINER_INFORMATION = _TOKEN_APPCONTAINER_INFORMATION
PTOKEN_APPCONTAINER_INFORMATION = POINTER(TOKEN_APPCONTAINER_INFORMATION)

TOKEN_APPCONTAINER_SID_MAX_SIZE = sizeof(TOKEN_APPCONTAINER_INFORMATION()) + SECURITY_MAX_SID_SIZE

class _TOKEN_SID_INFORMATION(Structure):
    _fields_ = [('Sid', PSID)]

TOKEN_SID_INFORMATION = _TOKEN_SID_INFORMATION
PTOKEN_SID_INFORMATION = POINTER(TOKEN_SID_INFORMATION)

class _TOKEN_BNO_ISOLATION_INFORMATION(Structure):
    _fields_ = [('IsolationPrefix', PWSTR),
                ('IsolationEnabled', BOOLEAN)
    ]

TOKEN_BNO_ISOLATION_INFORMATION = _TOKEN_BNO_ISOLATION_INFORMATION
PTOKEN_BNO_ISOLATION_INFORMATION = POINTER(TOKEN_BNO_ISOLATION_INFORMATION)

CLAIM_SECURITY_ATTRIBUTE_TYPE_INVALID = 0x00
CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64 = 0x01
CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64 = 0x02
CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING = 0x03
CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN = 0x04
CLAIM_SECURITY_ATTRIBUTE_TYPE_SID = 0x05
CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN = 0x06

class _CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE(Structure):
    _fields_ = [('Version', DWORD64),
                ('Name', PWSTR)
    ]

CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE = _CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE
PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE = POINTER(CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE)

class _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE(Structure):
    _fields_ = [('pValue', PVOID), 
                ('ValueLength', DWORD)
    ]

CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE = _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE = POINTER(CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)

CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING = 0x10
CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE = 0x0001
CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE = 0x0002
CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY = 0x0004
CLAIM_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT = 0x0008
CLAIM_SECURITY_ATTRIBUTE_DISABLED = 0x0010
CLAIM_SECURITY_ATTRIBUTE_MANDATORY = 0x0020

CLAIM_SECURITY_ATTRIBUTE_VALID_FLAGS = (CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE | 
                                        CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE | 
                                        CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY | 
                                        CLAIM_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT | 
                                        CLAIM_SECURITY_ATTRIBUTE_DISABLED | 
                                        CLAIM_SECURITY_ATTRIBUTE_MANDATORY
)

CLAIM_SECURITY_ATTRIBUTE_CUSTOM_FLAGS = 0xffff0000

class _CLAIM_SECURITY_ATTRIBUTE_V1(Structure):
    class Values(Union):
        _fields_ = [('pInt64', PLONG64),
                    ('pUint64', PDWORD64),
                    ('ppString', POINTER(PWSTR)),
                    ('pFqbn', PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE),
                    ('pOctetString', PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)
        ]

    _anonymous_ = ['Values']
    _fields_ = [('Name', PWSTR),
                ('ValueType', WORD),
                ('Reserved', WORD),
                ('Flags', DWORD),
                ('ValueCount', DWORD),
                ('Values', Values)
    ]

CLAIM_SECURITY_ATTRIBUTE_V1 = _CLAIM_SECURITY_ATTRIBUTE_V1
PCLAIM_SECURITY_ATTRIBUTE_V1 = POINTER(CLAIM_SECURITY_ATTRIBUTE_V1)

class _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1(Structure):
    class Values(Union):
        _fields_ = [('pInt64', DWORD * ANYSIZE_ARRAY),
                    ('pUint64', DWORD * ANYSIZE_ARRAY),
                    ('ppString', DWORD * ANYSIZE_ARRAY),
                    ('pFqbn', DWORD * ANYSIZE_ARRAY),
                    ('pOctetString', DWORD * ANYSIZE_ARRAY)
        ]

    _anonymous_ = ['Values']
    _fields_ = [('Name', DWORD),
                ('ValueType', WORD),
                ('Reserved', WORD),
                ('Flags', DWORD),
                ('ValueCount', DWORD),
                ('Values', Values),
    ]

CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 = _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 = POINTER(CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1)

CLAIM_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1 = 1

CLAIM_SECURITY_ATTRIBUTES_INFORMATION_VERSION = CLAIM_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1

class _CLAIM_SECURITY_ATTRIBUTES_INFORMATION(Structure):
    class Attribute(Union):
        _fields_ = [('pAttributeV1', PCLAIM_SECURITY_ATTRIBUTE_V1)]

    _anonymous_ = ['Attribute']
    _fields_ = [('Version', WORD),
                ('Reserved', WORD),
                ('AttributeCount', DWORD),
                ('Attribute', Attribute),
    ]

CLAIM_SECURITY_ATTRIBUTES_INFORMATION = _CLAIM_SECURITY_ATTRIBUTES_INFORMATION
PCLAIM_SECURITY_ATTRIBUTES_INFORMATION = POINTER(CLAIM_SECURITY_ATTRIBUTES_INFORMATION)

SECURITY_DYNAMIC_TRACKING = True
SECURITY_STATIC_TRACKING = False

SECURITY_CONTEXT_TRACKING_MODE = BOOLEAN
PSECURITY_CONTEXT_TRACKING_MODE = PBOOLEAN

class _SECURITY_QUALITY_OF_SERVICE(Structure):
    _fields_ = [('Length', DWORD),
                ('ImpersonationLevel', UINT),
                ('ContextTrackingMode', SECURITY_CONTEXT_TRACKING_MODE),
                ('EffectiveOnly', BOOLEAN)
    ]

SECURITY_QUALITY_OF_SERVICE = _SECURITY_QUALITY_OF_SERVICE
PSECURITY_QUALITY_OF_SERVICE = POINTER(SECURITY_QUALITY_OF_SERVICE)

class _SE_IMPERSONATION_STATE(Structure):
    _fields_ = [('Token', PACCESS_TOKEN),
                ('CopyOnOpen', BOOLEAN),
                ('EffectiveOnly', BOOLEAN),
                ('Level', UINT)
    ]

SE_IMPERSONATION_STATE = _SE_IMPERSONATION_STATE
PSE_IMPERSONATION_STATE = POINTER(SE_IMPERSONATION_STATE)

DISABLE_MAX_PRIVILEGE = 0x1
SANDBOX_INERT = 0x2
LUA_TOKEN = 0x4
WRITE_RESTRICTED = 0x8

SECURITY_INFORMATION = DWORD
PSECURITY_INFORMATION = PDWORD

OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
SACL_SECURITY_INFORMATION = 0x00000008
LABEL_SECURITY_INFORMATION = 0x00000010
ATTRIBUTE_SECURITY_INFORMATION = 0x00000020
SCOPE_SECURITY_INFORMATION = 0x00000040
PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080
ACCESS_FILTER_SECURITY_INFORMATION = 0x00000100
BACKUP_SECURITY_INFORMATION = 0x00010000

PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000

SE_SIGNING_LEVEL = BYTE
PSE_SIGNING_LEVEL = PBYTE

SE_SIGNING_LEVEL_UNCHECKED = 0x00000000
SE_SIGNING_LEVEL_ = 0x00000001
SE_SIGNING_LEVEL_ENTERPRISE = 0x00000002
SE_SIGNING_LEVEL_CUSTOM_1 = 0x00000003
SE_SIGNING_LEVEL_DEVELOPER = SE_SIGNING_LEVEL_CUSTOM_1
SE_SIGNING_LEVEL_AUTHENTICODE = 0x00000004
SE_SIGNING_LEVEL_CUSTOM_2 = 0x00000005
SE_SIGNING_LEVEL_STORE = 0x00000006
SE_SIGNING_LEVEL_CUSTOM_3 = 0x00000007
SE_SIGNING_LEVEL_ANTIMALWARE = SE_SIGNING_LEVEL_CUSTOM_3
SE_SIGNING_LEVEL_MICROSOFT = 0x00000008
SE_SIGNING_LEVEL_CUSTOM_4 = 0x00000009
SE_SIGNING_LEVEL_CUSTOM_5 = 0x0000000A
SE_SIGNING_LEVEL_DYNAMIC_CODEGEN = 0x0000000B
SE_SIGNING_LEVEL_WINDOWS = 0x0000000C
SE_SIGNING_LEVEL_CUSTOM_7 = 0x0000000D
SE_SIGNING_LEVEL_WINDOWS_TCB = 0x0000000E
SE_SIGNING_LEVEL_CUSTOM_6 = 0x0000000F

SeImageSignatureNone = 0
SeImageSignatureEmbedded = 1
SeImageSignatureCache = 2
SeImageSignatureCatalogCached = 3
SeImageSignatureCatalogNotCached = 4
SeImageSignatureCatalogHint = 5
SeImageSignaturePackageCatalog = 6
SeImageSignaturePplMitigated = 7

class _SE_IMAGE_SIGNATURE_TYPE(enum.IntFlag):
    SeImageSignatureNone = 0
    SeImageSignatureEmbedded = 1
    SeImageSignatureCache = 2
    SeImageSignatureCatalogCached = 3
    SeImageSignatureCatalogNotCached = 4
    SeImageSignatureCatalogHint = 5
    SeImageSignaturePackageCatalog = 6
    SeImageSignaturePplMitigated = 7

SE_IMAGE_SIGNATURE_TYPE = _SE_IMAGE_SIGNATURE_TYPE
PSE_IMAGE_SIGNATURE_TYPE = SE_IMAGE_SIGNATURE_TYPE

SeLearningModeInvalidType = 0
SeLearningModeSettings = 1
SeLearningModeMax = 2

class _SE_LEARNING_MODE_DATA_TYPE(enum.IntFlag):
    SeLearningModeInvalidType = 0
    SeLearningModeSettings = 1
    SeLearningModeMax = 2

SE_LEARNING_MODE_DATA_TYPE = _SE_LEARNING_MODE_DATA_TYPE

SE_LEARNING_MODE_FLAG_PERMISSIVE = 0x00000001

class _SECURITY_CAPABILITIES(Structure):
    _fields_ = [('AppContainerSid', PSID),
                ('Capabilities', PSID_AND_ATTRIBUTES),
                ('CapabilityCount', DWORD),
                ('Reserved', DWORD),
    ]

SECURITY_CAPABILITIES = _SECURITY_CAPABILITIES
PSECURITY_CAPABILITIES = POINTER(SECURITY_CAPABILITIES)
LPSECURITY_CAPABILITIES = PSECURITY_CAPABILITIES

PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_SET_SESSIONID = 0x0004
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_CREATE_PROCESS = 0x0080
PROCESS_SET_QUOTA = 0x0100
PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_SET_LIMITED_INFORMATION = 0x2000

if NTDDI_VERSION >= NTDDI_VISTA:
    PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xffff)
    THREAD_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xffff)
else:
    PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xfff)
    THREAD_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3ff)

if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32:
    MAXIMUM_PROC_PER_GROUP = 64
else:
    MAXIMUM_PROC_PER_GROUP = 32

MAXIMUM_PROCESSORS = MAXIMUM_PROC_PER_GROUP

THREAD_TERMINATE = 0x0001
THREAD_SUSPEND_RESUME = 0x0002
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SET_INFORMATION = 0x0020
THREAD_QUERY_INFORMATION = 0x0040
THREAD_SET_THREAD_TOKEN = 0x0080
THREAD_IMPERSONATE = 0x0100
THREAD_DIRECT_IMPERSONATION = 0x0200
THREAD_SET_LIMITED_INFORMATION = 0x0400
THREAD_QUERY_LIMITED_INFORMATION = 0x0800
THREAD_RESUME = 0x1000

JOB_OBJECT_ASSIGN_PROCESS = 0x0001
JOB_OBJECT_SET_ATTRIBUTES = 0x0002
JOB_OBJECT_QUERY = 0x0004
JOB_OBJECT_TERMINATE = 0x0008
JOB_OBJECT_SET_SECURITY_ATTRIBUTES = 0x0010
JOB_OBJECT_IMPERSONATE = 0x0020
JOB_OBJECT_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                         SYNCHRONIZE | 
                         0x3F
)

class _JOB_SET_ARRAY(Structure):
    _fields_ = [('JobHandle', HANDLE),
                ('MemberLevel', DWORD),
                ('Flags', DWORD)
    ]

JOB_SET_ARRAY = _JOB_SET_ARRAY
PJOB_SET_ARRAY = POINTER(JOB_SET_ARRAY)

if NTDDI_VERSION >= NTDDI_WIN10_19H1:
    FLS_MAXIMUM_AVAILABLE = 4080
else:
    FLS_MAXIMUM_AVAILABLE = 128

TLS_MINIMUM_AVAILABLE = 64

class NeprUnion(Union):
    pass

class _EXCEPTION_REGISTRATION_RECORD(Structure):
    pass

class HahaUnion(Union):
    _fields_ = [('Handler', PEXCEPTION_ROUTINE),
                ('handler', PEXCEPTION_ROUTINE)
    ]

NeprUnion._fields_ = [('Next', POINTER(_EXCEPTION_REGISTRATION_RECORD)),
                      ('prev', POINTER(_EXCEPTION_REGISTRATION_RECORD))
]

_EXCEPTION_REGISTRATION_RECORD._anonymous_ = ['HahaUnion', 'NeprUnion']
_EXCEPTION_REGISTRATION_RECORD._fields_ = [('HahaUnion', HahaUnion),
                                           ('NeprUnion', NeprUnion)
]

EXCEPTION_REGISTRATION_RECORD = _EXCEPTION_REGISTRATION_RECORD
PEXCEPTION_REGISTRATION_RECORD = POINTER(EXCEPTION_REGISTRATION_RECORD)

EXCEPTION_REGISTRATION = EXCEPTION_REGISTRATION_RECORD
PEXCEPTION_REGISTRATION = PEXCEPTION_REGISTRATION_RECORD

class _NT_TIB(Structure):
    class FibVerUnion(Union):
        _fields_ = [('FiberData', PVOID),
                    ('Version', DWORD)
        ]

    _anonymous_= ['FibVerUnion']
    _fields_ = [('ExceptionList', POINTER(_EXCEPTION_REGISTRATION_RECORD)),
                ('StackBase', PVOID),
                ('StackLimit', PVOID),
                ('SubSystemTib', PVOID),
                ('FibVerUnion', FibVerUnion),
                ('ArbitraryUserPointer', PVOID)
    ]

_NT_TIB._fields_.append(('Self', POINTER(_NT_TIB)))

NT_TIB = _NT_TIB
PNT_TIB = POINTER(NT_TIB)

class _NT_TIB32(Structure):
    class FibVerUnion(Union):
        _fields_ = [('FiberData', DWORD),
                    ('Version', DWORD)
        ]

    _anonymous_ = ['FibVerUnion']
    _fields_ = [('ExceptionList', DWORD),
                ('StackBase', DWORD),
                ('StackLimit', DWORD),
                ('SubSystemTib', DWORD),
                ('FibVerUnion', FibVerUnion),
                ('ArbitraryUserPointer', DWORD),
                ('Self', DWORD)
    ]

NT_TIB32 = _NT_TIB32
PNT_TIB32 = POINTER(NT_TIB32)

class _NT_TIB64(Structure):
    class FibVerUnion(Union):
        _fields_ = [('FiberData', DWORD64),
                    ('Version', DWORD64)
        ]

    _anonymous_ = ['FibVerUnion']
    _fields_ = [('ExceptionList', DWORD64),
                ('StackBase', DWORD64),
                ('StackLimit', DWORD64),
                ('SubSystemTib', DWORD64),
                ('FibVerUnion', FibVerUnion),
                ('ArbitraryUserPointer', DWORD64),
                ('Self', DWORD64)
    ]

NT_TIB64 = _NT_TIB64
PNT_TIB64 = POINTER(NT_TIB64)

THREAD_DYNAMIC_CODE_ALLOW = 1

THREAD_BASE_PRIORITY_LOWRT = 15
THREAD_BASE_PRIORITY_MAX = 2
THREAD_BASE_PRIORITY_MIN = -2
THREAD_BASE_PRIORITY_IDLE = -15

class _UMS_CREATE_THREAD_ATTRIBUTES(Structure):
    _fields_ = [('UmsVersion', DWORD),
                ('UmsContext', PVOID),
                ('UmsCompletionList', PVOID),
    ]

UMS_CREATE_THREAD_ATTRIBUTES = _UMS_CREATE_THREAD_ATTRIBUTES
PUMS_CREATE_THREAD_ATTRIBUTES = POINTER(UMS_CREATE_THREAD_ATTRIBUTES)

COMPONENT_KTM = 0x01
COMPONENT_VALID_FLAGS = COMPONENT_KTM

class _COMPONENT_FILTER(Structure):
    _fields_ = [('ComponentFlags', DWORD)]    

COMPONENT_FILTER = _COMPONENT_FILTER
PCOMPONENT_FILTER = POINTER(COMPONENT_FILTER)

DYNAMIC_EH_CONTINUATION_TARGET_ADD = 0x00000001
DYNAMIC_EH_CONTINUATION_TARGET_PROCESSED = 0x00000002

class _PROCESS_DYNAMIC_EH_CONTINUATION_TARGET(Structure):
    _fields_ = [('TargetAddress', ULONG_PTR),
                ('Flags', ULONG_PTR)
    ]

PROCESS_DYNAMIC_EH_CONTINUATION_TARGET = _PROCESS_DYNAMIC_EH_CONTINUATION_TARGET
PPROCESS_DYNAMIC_EH_CONTINUATION_TARGET = POINTER(PROCESS_DYNAMIC_EH_CONTINUATION_TARGET)

class _PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION(Structure):
    _fields_ = [('NumberOfTargets', WORD),
                ('Reserved', WORD),
                ('Reserved2', DWORD),
                ('Targets', PPROCESS_DYNAMIC_EH_CONTINUATION_TARGET),
    ]

PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION = _PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
PPROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION = POINTER(PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION)

DYNAMIC_ENFORCED_ADDRESS_RANGE_ADD = 0x00000001
DYNAMIC_ENFORCED_ADDRESS_RANGE_PROCESSED = 0x00000002

class _PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE(Structure):
    _fields_ = [('BaseAddress', ULONG_PTR),
                ('Size', SIZE_T),
                ('Flags', DWORD)
    ]

PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE = _PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE
PPROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE = POINTER(PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE)

class _PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION(Structure):
    _fields_ = [('NumberOfRanges', WORD),
                ('Reserved', WORD),
                ('Reserved2', DWORD),
                ('Ranges', PPROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE),
    ]

PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION = _PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION
PPROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION = POINTER(PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION)

class _QUOTA_LIMITS(Structure):
    _fields_ = [('PagedPoolLimit', SIZE_T),
                ('NonPagedPoolLimit', SIZE_T),
                ('MinimumWorkingSetSize', SIZE_T),
                ('MaximumWorkingSetSize', SIZE_T),
                ('PagefileLimit', SIZE_T),
                ('TimeLimit', LARGE_INTEGER),
    ]

QUOTA_LIMITS = _QUOTA_LIMITS
PQUOTA_LIMITS = POINTER(QUOTA_LIMITS)

QUOTA_LIMITS_HARDWS_MIN_ENABLE = 0x00000001
QUOTA_LIMITS_HARDWS_MIN_DISABLE = 0x00000002
QUOTA_LIMITS_HARDWS_MAX_ENABLE = 0x00000004
QUOTA_LIMITS_HARDWS_MAX_DISABLE = 0x00000008
QUOTA_LIMITS_USE_DEFAULT_LIMITS = 0x00000010

class _RATE_QUOTA_LIMIT(Union):
    class RatResLittleStruct(LittleEndianStructure):
        _fields_ = [('RatePercent', DWORD, 7),
                    ('Reserved0', DWORD, 25)
        ]

    _anonymous_ = ['RatResLittleStruct']
    _fields_ = [('RateData', DWORD),
                ('RatResLittleStruct', RatResLittleStruct)
    ]

RATE_QUOTA_LIMIT = _RATE_QUOTA_LIMIT
PRATE_QUOTA_LIMIT = POINTER(RATE_QUOTA_LIMIT)

class _QUOTA_LIMITS_EX(Structure):
    _fields_ = [('PagedPoolLimit', SIZE_T),
                ('NonPagedPoolLimit', SIZE_T),
                ('MinimumWorkingSetSize', SIZE_T),
                ('MaximumWorkingSetSize', SIZE_T),
                ('PagefileLimit', SIZE_T),
                ('TimeLimit', LARGE_INTEGER),
                ('WorkingSetLimit', SIZE_T),
                ('Reserved2', SIZE_T),
                ('Reserved3', SIZE_T),
                ('Reserved4', SIZE_T),
                ('Flags', DWORD),
                ('CpuRateLimit', RATE_QUOTA_LIMIT)
    ]

QUOTA_LIMITS_EX = _QUOTA_LIMITS_EX
PQUOTA_LIMITS_EX = POINTER(QUOTA_LIMITS_EX)

class _IO_COUNTERS(Structure):
    _fields_ = [('ReadOperationCount', ULONGLONG),
                ('WriteOperationCount', ULONGLONG),
                ('OtherOperationCount', ULONGLONG),
                ('ReadTransferCount', ULONGLONG),
                ('WriteTransferCount', ULONGLONG),
                ('OtherTransferCount', ULONGLONG)
    ]

IO_COUNTERS = _IO_COUNTERS
PIO_COUNTERS = POINTER(IO_COUNTERS)

MAX_HW_COUNTERS = 16
THREAD_PROFILING_FLAG_DISPATCH = 0x1

PMCCounter = 0
MaxHardwareCounterType = 1

class _HARDWARE_COUNTER_TYPE(enum.IntFlag):
    PMCCounter = 0
    MaxHardwareCounterType = 1

HARDWARE_COUNTER_TYPE = _HARDWARE_COUNTER_TYPE
PHARDWARE_COUNTER_TYPE = HARDWARE_COUNTER_TYPE

ProcessDEPPolicy = 0
ProcessASLRPolicy = 1
ProcessDynamicCodePolicy = 2
ProcessStrictHandleCheckPolicy = 3
ProcessSystemCallDisablePolicy = 4
ProcessMitigationOptionsMask = 5
ProcessExtensionPointDisablePolicy = 6
ProcessControlFlowGuardPolicy = 7
ProcessSignaturePolicy = 8
ProcessFontDisablePolicy = 9
ProcessImageLoadPolicy = 10
ProcessSystemCallFilterPolicy = 11
ProcessPayloadRestrictionPolicy = 12
ProcessChildProcessPolicy = 13
ProcessSideChannelIsolationPolicy = 14
ProcessUserShadowStackPolicy = 15
ProcessRedirectionTrustPolicy = 16
ProcessUserPointerAuthPolicy = 17
ProcessSEHOPPolicy = 18
MaxProcessMitigationPolicy = 19

class _PROCESS_MITIGATION_POLICY(enum.IntFlag):
    ProcessDEPPolicy = 0
    ProcessASLRPolicy = 1
    ProcessDynamicCodePolicy = 2
    ProcessStrictHandleCheckPolicy = 3
    ProcessSystemCallDisablePolicy = 4
    ProcessMitigationOptionsMask = 5
    ProcessExtensionPointDisablePolicy = 6
    ProcessControlFlowGuardPolicy = 7
    ProcessSignaturePolicy = 8
    ProcessFontDisablePolicy = 9
    ProcessImageLoadPolicy = 10
    ProcessSystemCallFilterPolicy = 11
    ProcessPayloadRestrictionPolicy = 12
    ProcessChildProcessPolicy = 13
    ProcessSideChannelIsolationPolicy = 14
    ProcessUserShadowStackPolicy = 15
    ProcessRedirectionTrustPolicy = 16
    ProcessUserPointerAuthPolicy = 17
    ProcessSEHOPPolicy = 18
    MaxProcessMitigationPolicy = 19

PROCESS_MITIGATION_POLICY = _PROCESS_MITIGATION_POLICY
PPROCESS_MITIGATION_POLICY = PROCESS_MITIGATION_POLICY

class _PROCESS_MITIGATION_ASLR_POLICY(Structure):
    class FlagsUnion(Union):
        class EnaDisResLittleStruct(LittleEndianStructure):
            _fields_ = [('EnableBottomUpRandomization', DWORD, 1),
                        ('EnableForceRelocateImages', DWORD, 1),
                        ('EnableHighEntropy', DWORD, 1),
                        ('DisallowStrippedImages', DWORD, 1),
                        ('ReservedFlags', DWORD, 28)
            ]
        
        _anonymous_ = ['EnaDisResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('EnaDisResLittleStruct', EnaDisResLittleStruct)
        ]
    
    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_ASLR_POLICY = _PROCESS_MITIGATION_ASLR_POLICY
PPROCESS_MITIGATION_ASLR_POLICY = POINTER(PROCESS_MITIGATION_ASLR_POLICY)

class _PROCESS_MITIGATION_DEP_POLICY(Structure):
    class FlagsUnion(Union):
        class EnaDisResLittleStruct(LittleEndianStructure):
            _fields_ = [('Enable', DWORD, 1),
                        ('DisableAtlThunkEmulation', DWORD, 1),
                        ('ReservedFlags', DWORD, 30)
            ]
        
        _anonymous_ = ['EnaDisResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('EnaDisResLittleStruct', EnaDisResLittleStruct)
        ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion),
                ('Permanent', BOOLEAN)
    ]

PROCESS_MITIGATION_DEP_POLICY = _PROCESS_MITIGATION_DEP_POLICY
PPROCESS_MITIGATION_DEP_POLICY = POINTER(PROCESS_MITIGATION_DEP_POLICY)

class _PROCESS_MITIGATION_SEHOP_POLICY(Structure):
    class FlagsUnion(Union):
        class EnaResLittleStruct(LittleEndianStructure):
            _fields_ = [('EnableSehop', DWORD, 1),
                        ('ReservedFlags', DWORD, 31)
            ]
        
        _anonymous_ = ['EnaResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('EnaResLittleStruct', EnaResLittleStruct)
        ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_SEHOP_POLICY = _PROCESS_MITIGATION_SEHOP_POLICY
PPROCESS_MITIGATION_SEHOP_POLICY = POINTER(PROCESS_MITIGATION_SEHOP_POLICY)

class _PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY(Structure):
    class FlagsUnion(Union):
        class RaiHanResLittleStruct(LittleEndianStructure):
            _fields_ = [('RaiseExceptionOnInvalidHandleReference', DWORD, 1),
                        ('HandleExceptionsPermanentlyEnabled', DWORD, 1),
                        ('ReservedFlags', DWORD, 30)
            ]

        _anonymous_ = ['RaiHanResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('RaiHanResLittleStruct', RaiHanResLittleStruct)
        ]
     
    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY = _PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
PPROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY = POINTER(PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY)

class _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY(Structure):
    class FlagsUnion(Union):
        class DisResLittleStruct(LittleEndianStructure):
            _fields_ = [('DisallowWin32kSystemCalls', DWORD, 1),
                        ('ReservedFlags', DWORD, 31)
            ]

        _anonymous_ = ['DisResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('DisResLittleStruct', DisResLittleStruct)
        ]
    
    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY = _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
PPROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY = POINTER(PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY)

class _PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY(Structure):
    class FlagsUnion(Union):
        class DisResLittleStruct(LittleEndianStructure):
            _fields_ = [('DisableExtensionPoints', DWORD, 1),
                        ('ReservedFlags', DWORD, 31)
            ]
        
        _anonymous_ = ['DisResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('DisResLittleStruct', DisResLittleStruct)
        ]
    
    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY = _PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
PPROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY = POINTER(PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY)

class _PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY(Structure):
    class FlagsUnion(Union):
        class EnaStrResLittleStruct(LittleEndianStructure):
            _fields_ = [('EnableControlFlowGuard', DWORD, 1),
                        ('EnableExportSuppression', DWORD, 1),
                        ('StrictMode', DWORD, 1),
                        ('ReservedFlags', DWORD, 29)
            ]

        _anonymous_ = ['EnaStrResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('EnaStrResLittleStruct', EnaStrResLittleStruct)
        ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = _PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
PPROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = POINTER(PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY)

class _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY(Structure):
    class FlagsUnion(Union):
        class MicStoMitResLittleStruct(LittleEndianStructure):
            _fields_ = [('MicrosoftSignedOnly', DWORD, 1),
                        ('StoreSignedOnly', DWORD, 1),
                        ('MitigationOptIn', DWORD, 1),
                        ('ReservedFlags', DWORD, 29)
            ]
        
        _anonymous_ = ['MicStoMitResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('MicStoMitResLittleStruct', MicStoMitResLittleStruct)
        ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
PPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = POINTER(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY)

class _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY(Structure):
    class FlagsUnion(Union):
        class ProAllResLittleStruct(LittleEndianStructure):
            _fields_ = [('ProhibitDynamicCode', DWORD, 1),
                        ('AllowThreadOptOut', DWORD, 1),
                        ('AllowRemoteDowngrade', DWORD, 1),
                        ('ReservedFlags', DWORD, 29)
            ]
        
        _anonymous_ = ['ProAllResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('ProAllResLittleStruct', ProAllResLittleStruct)
        ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_DYNAMIC_CODE_POLICY = _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
PPROCESS_MITIGATION_DYNAMIC_CODE_POLICY = POINTER(PROCESS_MITIGATION_DYNAMIC_CODE_POLICY)

class _PROCESS_MITIGATION_FONT_DISABLE_POLICY(Structure):
    class FlagsUnion(Union):
        class DisAudResLittleStruct(LittleEndianStructure):
            _fields_ = [('DisableNonSystemFonts', DWORD, 1),
                        ('AuditNonSystemFontLoading', DWORD, 1),
                        ('ReservedFlags', DWORD, 30)
            ]
        
        _anonymous_ = ['DisAudResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('DisAudResLittleStruct', DisAudResLittleStruct)
        ]
    
    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_FONT_DISABLE_POLICY = _PROCESS_MITIGATION_FONT_DISABLE_POLICY
PPROCESS_MITIGATION_FONT_DISABLE_POLICY = POINTER(PROCESS_MITIGATION_FONT_DISABLE_POLICY)

class _PROCESS_MITIGATION_IMAGE_LOAD_POLICY(Structure):
    class FlagsUnion(Union):
        class NoPreResLittleStruct(LittleEndianStructure):
            _fields_ = [('NoRemoteImages', DWORD, 1),
                        ('NoLowMandatoryLabelImages', DWORD, 1),
                        ('PreferSystem32Images', DWORD, 1),
                        ('ReservedFlags', DWORD, 29)
            ]
        
        _anonymous_ = ['NoPreResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('NoPreResLittleStruct', NoPreResLittleStruct)
            ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_IMAGE_LOAD_POLICY = _PROCESS_MITIGATION_IMAGE_LOAD_POLICY
PPROCESS_MITIGATION_IMAGE_LOAD_POLICY = POINTER(PROCESS_MITIGATION_IMAGE_LOAD_POLICY)

class _PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY(Structure):
    class FlagsUnion(Union):
        class FilResLittleStruct(LittleEndianStructure):
            _fields_ = [('FilterId', DWORD, 4),
                        ('ReservedFlags', DWORD, 28)
            ]
        
        _anonymous_ = ['FilResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('FilResLittleStruct', FilResLittleStruct)
            ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY = _PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY
PPROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY = POINTER(PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY)

class _PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY(Structure):
    class FlagsUnion(Union):
        class EnaAudResLittleStruct(LittleEndianStructure):
            _fields_ = [('EnableExportAddressFilter', DWORD, 1),
                        ('AuditExportAddressFilter', DWORD, 1),
                        ('EnableExportAddressFilterPlus', DWORD, 1),
                        ('AuditExportAddressFilterPlus', DWORD, 1),
                        ('EnableImportAddressFilter', DWORD, 1),
                        ('AuditImportAddressFilter', DWORD, 1),
                        ('EnableRopStackPivot', DWORD, 1),
                        ('AuditRopStackPivot', DWORD, 1),
                        ('EnableRopCallerCheck', DWORD, 1),
                        ('AuditRopCallerCheck', DWORD, 1),
                        ('EnableRopSimExec', DWORD, 1),
                        ('AuditRopSimExec', DWORD, 1),
                        ('ReservedFlags', DWORD, 20)
            ]
        
        _anonymous_ = ['EnaAudResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('EnaAudResLittleStruct', EnaAudResLittleStruct)
        ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY = _PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY
PPROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY = POINTER(PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY)

class _PROCESS_MITIGATION_CHILD_PROCESS_POLICY(Structure):
    class FlagsUnion(Union):
        class NoAudAllResLittleStruct(LittleEndianStructure):
            _fields_ = [('NoChildProcessCreation', DWORD, 1),
                        ('AuditNoChildProcessCreation', DWORD, 1),
                        ('AllowSecureProcessCreation', DWORD, 1),
                        ('ReservedFlags', DWORD, 29)
            ]

        _anonymous_ = ['NoAudAllResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('NoAudAllResLittleStruct', NoAudAllResLittleStruct)
        ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_CHILD_PROCESS_POLICY = _PROCESS_MITIGATION_CHILD_PROCESS_POLICY
PPROCESS_MITIGATION_CHILD_PROCESS_POLICY = POINTER(PROCESS_MITIGATION_CHILD_PROCESS_POLICY)

class _PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY(Structure):
    class FlagsUnion(Union):
        class SmtIsoDisSpeResLittleStruct(LittleEndianStructure):
            _fields_ = [('SmtBranchTargetIsolation', DWORD, 1),
                        ('IsolateSecurityDomain', DWORD, 1),
                        ('DisablePageCombine', DWORD, 1),
                        ('SpeculativeStoreBypassDisable', DWORD, 1),
                        ('RestrictCoreSharing', DWORD, 1),
                        ('ReservedFlags', DWORD, 27)
            ]

        _anonymous_ = ['SmtIsoDisSpeResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('SmtIsoDisSpeResLittleStruct', SmtIsoDisSpeResLittleStruct)
            ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]   

PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY = _PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY
PPROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY = POINTER(PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY)

class _PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY(Structure):
    class FlagsUnion(Union):
        class EnaAudSetBloCetResLittleStruct(LittleEndianStructure):
            _fields_ = [('EnableUserShadowStack', DWORD, 1),
                        ('AuditUserShadowStack', DWORD, 1),
                        ('SetContextIpValidation', DWORD, 1),
                        ('AuditSetContextIpValidation', DWORD, 1),
                        ('EnableUserShadowStackStrictMode', DWORD, 1),
                        ('BlockNonCetBinaries', DWORD, 1),
                        ('BlockNonCetBinariesNonEhcont', DWORD, 1),
                        ('AuditBlockNonCetBinaries', DWORD, 1),
                        ('CetDynamicApisOutOfProcOnly', DWORD, 1),
                        ('SetContextIpValidationRelaxedMode', DWORD, 1),
                        ('ReservedFlags', DWORD, 22)
            ]

        _anonymous_ = ['EnaAudSetBloCetResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('EnaAudSetBloCetResLittleStruct', EnaAudSetBloCetResLittleStruct)
            ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY = _PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY
PPROCESS_MITIGATION_USER_SHADOW_STACK_POLICY = POINTER(PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY)

class _PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY(Structure):
    class FlagsUnion(Union):
        class EnaResLittleStruct(LittleEndianStructure):
            _fields_ = [('EnablePointerAuthUserIp', DWORD, 1),
                        ('ReservedFlags', DWORD, 31)
            ]
        
        _anonymous_ = ['EnaResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('EnaResLittleStruct', EnaResLittleStruct)
            ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY = _PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY
PPROCESS_MITIGATION_USER_POINTER_AUTH_POLICY = POINTER(PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY)

class _PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY(Structure):
    class FlagsUnion(Union):
        class EnfAudResLittleStruct(LittleEndianStructure):
            _fields_ = [('EnforceRedirectionTrust', DWORD, 1),
                        ('AuditRedirectionTrust', DWORD, 1),
                        ('ReservedFlags', DWORD, 30)
            ]
        
        _anonymous_ = ['EnfAudResLittleStruct']
        _fields_ = [('Flags', DWORD),
                    ('EnfAudResLittleStruct', EnfAudResLittleStruct)
            ]

    _anonymous_ = ['FlagsUnion']
    _fields_ = [('FlagsUnion', FlagsUnion)]

PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY = _PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY
PPROCESS_MITIGATION_REDIRECTION_TRUST_POLICY = POINTER(PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY)

class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(Structure):
    _fields_ = [('TotalUserTime', LARGE_INTEGER),
                ('TotalKernelTime', LARGE_INTEGER),
                ('ThisPeriodTotalUserTime', LARGE_INTEGER),
                ('ThisPeriodTotalKernelTime', LARGE_INTEGER),
                ('TotalPageFaultCount', DWORD),
                ('TotalProcesses', DWORD),
                ('ActiveProcesses', DWORD),
                ('TotalTerminatedProcesses', DWORD)
    ]

JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
PJOBOBJECT_BASIC_ACCOUNTING_INFORMATION = POINTER(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)

class _JOBOBJECT_BASIC_LIMIT_INFORMATION(Structure):
    _fields_ = [('PerProcessUserTimeLimit', LARGE_INTEGER),
                ('PerJobUserTimeLimit', LARGE_INTEGER),
                ('LimitFlags', DWORD),
                ('MinimumWorkingSetSize', SIZE_T),
                ('MaximumWorkingSetSize', SIZE_T),
                ('ActiveProcessLimit', DWORD),
                ('Affinity', ULONG_PTR),
                ('PriorityClass', DWORD),
                ('SchedulingClass', DWORD)
    ]

JOBOBJECT_BASIC_LIMIT_INFORMATION = _JOBOBJECT_BASIC_LIMIT_INFORMATION
PJOBOBJECT_BASIC_LIMIT_INFORMATION = POINTER(JOBOBJECT_BASIC_LIMIT_INFORMATION)

class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(Structure):
    _fields_ = [('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ('IoInfo', IO_COUNTERS),
                ('ProcessMemoryLimit', SIZE_T),
                ('JobMemoryLimit', SIZE_T),
                ('PeakProcessMemoryUsed', SIZE_T),
                ('PeakJobMemoryUsed', SIZE_T)
    ]

JOBOBJECT_EXTENDED_LIMIT_INFORMATION = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION
PJOBOBJECT_EXTENDED_LIMIT_INFORMATION = POINTER(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)

class _JOBOBJECT_BASIC_PROCESS_ID_LIST(Structure):
    _fields_ = [('NumberOfAssignedProcesses', DWORD),
                ('NumberOfProcessIdsInList', DWORD),
                ('ProcessIdList', ULONG_PTR * 1)
    ]

JOBOBJECT_BASIC_PROCESS_ID_LIST = _JOBOBJECT_BASIC_PROCESS_ID_LIST
PJOBOBJECT_BASIC_PROCESS_ID_LIST = POINTER(JOBOBJECT_BASIC_PROCESS_ID_LIST)

class _JOBOBJECT_BASIC_UI_RESTRICTIONS(Structure):
    _fields_ = [('UIRestrictionsClass', DWORD)]

JOBOBJECT_BASIC_UI_RESTRICTIONS = _JOBOBJECT_BASIC_UI_RESTRICTIONS
PJOBOBJECT_BASIC_UI_RESTRICTIONS = POINTER(JOBOBJECT_BASIC_UI_RESTRICTIONS)

class _JOBOBJECT_SECURITY_LIMIT_INFORMATION(Structure):
    _fields_ = [('SecurityLimitFlags', DWORD),
                ('JobToken', HANDLE),
                ('SidsToDisable', PTOKEN_GROUPS),
                ('PrivilegesToDelete', PTOKEN_PRIVILEGES),
                ('RestrictedSids', PTOKEN_GROUPS)
    ]

JOBOBJECT_SECURITY_LIMIT_INFORMATION = _JOBOBJECT_SECURITY_LIMIT_INFORMATION
PJOBOBJECT_SECURITY_LIMIT_INFORMATION = POINTER(JOBOBJECT_SECURITY_LIMIT_INFORMATION)

class _JOBOBJECT_END_OF_JOB_TIME_INFORMATION(Structure):
    _fields_ = [('EndOfJobTimeAction', DWORD)]

JOBOBJECT_END_OF_JOB_TIME_INFORMATION = _JOBOBJECT_END_OF_JOB_TIME_INFORMATION
PJOBOBJECT_END_OF_JOB_TIME_INFORMATION = POINTER(JOBOBJECT_END_OF_JOB_TIME_INFORMATION)

class _JOBOBJECT_ASSOCIATE_COMPLETION_PORT(Structure):
    _fields_ = [('CompletionKey', PVOID),
                ('CompletionPort', HANDLE)
    ]

JOBOBJECT_ASSOCIATE_COMPLETION_PORT = _JOBOBJECT_ASSOCIATE_COMPLETION_PORT
PJOBOBJECT_ASSOCIATE_COMPLETION_PORT = POINTER(JOBOBJECT_ASSOCIATE_COMPLETION_PORT)

class _JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION(Structure):
    _fields_ = [('BasicInfo', JOBOBJECT_BASIC_ACCOUNTING_INFORMATION),
                ('IoInfo', IO_COUNTERS)
    ]

JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION = _JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION
PJOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION = POINTER(JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION)

class _JOBOBJECT_JOBSET_INFORMATION(Structure):
    _fields_ = [('MemberLevel', DWORD)]

JOBOBJECT_JOBSET_INFORMATION = _JOBOBJECT_JOBSET_INFORMATION
PJOBOBJECT_JOBSET_INFORMATION = POINTER(JOBOBJECT_JOBSET_INFORMATION)

ToleranceLow = 1
ToleranceMedium = 2
ToleranceHigh = 3

class _JOBOBJECT_RATE_CONTROL_TOLERANCE(enum.IntFlag):
    ToleranceLow = 1
    ToleranceMedium = 2
    ToleranceHigh = 3

JOBOBJECT_RATE_CONTROL_TOLERANCE = _JOBOBJECT_RATE_CONTROL_TOLERANCE

ToleranceIntervalShort = 1
ToleranceIntervalMedium = 2
ToleranceIntervalLong = 3

class _JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL(enum.IntFlag):
    ToleranceIntervalShort = 1
    ToleranceIntervalMedium = 2
    ToleranceIntervalLong = 3

JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL = _JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL

class _JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION(Structure):
    _fields_ = [('IoReadBytesLimit', DWORD64),
                ('IoWriteBytesLimit', DWORD64),
                ('PerJobUserTimeLimit', LARGE_INTEGER),
                ('JobMemoryLimit', DWORD64),
                ('RateControlTolerance', UINT),
                ('RateControlToleranceInterval', UINT),
                ('LimitFlags', DWORD)
    ]

JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION = _JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION
PJOBOBJECT_NOTIFICATION_LIMIT_INFORMATION = POINTER(JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION)

class JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2(Structure):
    class JobUnion(Union):
        _fields_ = [('JobHighMemoryLimit', DWORD64),
                    ('JobMemoryLimit', DWORD64)
        ]
    
    class RatCpuUnion(Union):
        _fields_ = [('RateControlTolerance', UINT),
                    ('CpuRateControlTolerance', UINT)
        ]
    
    class RatCpuUnion2(Union):
        _fields_ = [('RateControlToleranceInterval', UINT),
                    ('CpuRateControlToleranceInterval', UINT)
        ]
    
    _anonymous_ = ['RatCpuUnion', 'RatCpuUnion2', 'JobUnion']
    _fields_ = [('IoReadBytesLimit', DWORD64),
                ('IoWriteBytesLimit', DWORD64),
                ('PerJobUserTimeLimit', LARGE_INTEGER),
                ('JobUnion', JobUnion),
                ('RatCpuUnion', RatCpuUnion),
                ('RatCpuUnion2', RatCpuUnion2),
                ('LimitFlags', DWORD),
                ('IoRateControlTolerance', UINT),
                ('JobLowMemoryLimit', DWORD64),
                ('IoRateControlToleranceInterval', UINT),
                ('NetRateControlTolerance', UINT),
                ('NetRateControlToleranceInterval', UINT)
    ]

class _JOBOBJECT_LIMIT_VIOLATION_INFORMATION(Structure):
    _fields_ = [('LimitFlags', DWORD),
                ('ViolationLimitFlags', DWORD),
                ('IoReadBytes', DWORD64),
                ('IoReadBytesLimit', DWORD64),
                ('IoWriteBytes', DWORD64),
                ('IoWriteBytesLimit', DWORD64),
                ('PerJobUserTime', LARGE_INTEGER),
                ('PerJobUserTimeLimit', LARGE_INTEGER),
                ('JobMemory', DWORD64),
                ('JobMemoryLimit', DWORD64),
                ('RateControlTolerance', UINT),
                ('RateControlToleranceLimit', UINT)
    ]

JOBOBJECT_LIMIT_VIOLATION_INFORMATION = _JOBOBJECT_LIMIT_VIOLATION_INFORMATION
PJOBOBJECT_LIMIT_VIOLATION_INFORMATION = POINTER(JOBOBJECT_LIMIT_VIOLATION_INFORMATION)

class JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2(Structure):
    class JobUnion(Union):
        _fields_ = [('JobHighMemoryLimit', DWORD64),
                    ('JobMemoryLimit', DWORD64)
        ]
    
    class RatCpuUnion(Union):
        _fields_ = [('RateControlTolerance', UINT),
                    ('CpuRateControlTolerance', UINT)
        ]
    
    class RatCpuUnion2(Union):
        _fields_ = [('RateControlToleranceInterval', UINT),
                    ('CpuRateControlToleranceInterval', UINT)
        ]
    
    _anonymous_ = ['JobUnion', 'RatCpuUnion', 'RatCpuUnion2']
    _fields_ = [('LimitFlags', DWORD),
                ('ViolationLimitFlags', DWORD),
                ('IoReadBytes', DWORD64),
                ('IoReadBytesLimit', DWORD64),
                ('IoWriteBytes', DWORD64),
                ('IoWriteBytesLimit', DWORD64),
                ('PerJobUserTime', LARGE_INTEGER),
                ('PerJobUserTimeLimit', LARGE_INTEGER),
                ('JobMemory', DWORD64),
                ('JobMemoryLimit', DWORD64),
                ('IoRateControlTolerance', UINT),
                ('IoRateControlToleranceLimit', UINT),
                ('NetRateControlTolerance', UINT),
                ('NetRateControlToleranceLimit', UINT),
                ('JobUnion', JobUnion),
                ('RatCpuUnion', RatCpuUnion),
                ('RatCpuUnion2', RatCpuUnion2)
    ]

class _JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(Structure):
    class CpuWeiUnion(Union):
        _fields_ = [('CpuRate', DWORD),
                    ('Weight', DWORD)
        ]

    _anonymous_ = ['CpuWeiUnion']
    _fields_ = [('ControlFlags', DWORD),
                ('CpuWeiUnion', CpuWeiUnion)
    ]

JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = _JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
PJOBOBJECT_CPU_RATE_CONTROL_INFORMATION = POINTER(JOBOBJECT_CPU_RATE_CONTROL_INFORMATION)

JOB_OBJECT_NET_RATE_CONTROL_ENABLE = 0x1
JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH = 0x2
JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG = 0x4
JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS = 0x7

class JOB_OBJECT_NET_RATE_CONTROL_FLAGS(enum.IntFlag):
    JOB_OBJECT_NET_RATE_CONTROL_ENABLE = 0x1
    JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH = 0x2
    JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG = 0x4
    JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS = 0x7


JOB_OBJECT_NET_RATE_CONTROL_MAX_DSCP_TAG = 64

class JOBOBJECT_NET_RATE_CONTROL_INFORMATION(Structure):
    _fields_ = [('MaxBandwidth', DWORD64),
                ('ControlFlags', UINT),
                ('DscpTag', BYTE)
    ]

JOB_OBJECT_IO_RATE_CONTROL_ENABLE = 0x1
JOB_OBJECT_IO_RATE_CONTROL_STANDALONE_VOLUME = 0x2
JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ALL = 0x4
JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ON_SOFT_CAP = 0x8
JOB_OBJECT_IO_RATE_CONTROL_VALID_FLAGS = (JOB_OBJECT_IO_RATE_CONTROL_ENABLE | 
                                          JOB_OBJECT_IO_RATE_CONTROL_STANDALONE_VOLUME | 
                                          JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ALL | 
                                          JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ON_SOFT_CAP
)

class JOB_OBJECT_IO_RATE_CONTROL_FLAGS(enum.IntFlag):
    JOB_OBJECT_IO_RATE_CONTROL_ENABLE = 0x1
    JOB_OBJECT_IO_RATE_CONTROL_STANDALONE_VOLUME = 0x2
    JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ALL = 0x4
    JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ON_SOFT_CAP = 0x8
    JOB_OBJECT_IO_RATE_CONTROL_VALID_FLAGS = (JOB_OBJECT_IO_RATE_CONTROL_ENABLE | 
                                              JOB_OBJECT_IO_RATE_CONTROL_STANDALONE_VOLUME | 
                                              JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ALL | 
                                              JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ON_SOFT_CAP
    )

class JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE(Structure):
    _fields_ = [('MaxIops', LONG64),
                ('MaxBandwidth', LONG64),
                ('ReservationIops', LONG64),
                ('VolumeName', PWSTR),
                ('BaseIoSize', DWORD),
                ('ControlFlags', UINT),
                ('VolumeNameLength', WORD)
    ]

JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE_V1 = JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE

class JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE_V2(Structure):
    _fields_ = [('MaxIops', LONG64),
                ('MaxBandwidth', LONG64),
                ('ReservationIops', LONG64),
                ('VolumeName', PWSTR),
                ('BaseIoSize', DWORD),
                ('ControlFlags', UINT),
                ('VolumeNameLength', WORD),
                ('CriticalReservationIops', LONG64),
                ('ReservationBandwidth', LONG64),
                ('CriticalReservationBandwidth', LONG64),
                ('MaxTimePercent', LONG64),
                ('ReservationTimePercent', LONG64),
                ('CriticalReservationTimePercent', LONG64)
    ]

class JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE_V3(Structure):
    _fields_ = [('MaxIops', LONG64),
                ('MaxBandwidth', LONG64),
                ('ReservationIops', LONG64),
                ('VolumeName', PWSTR),
                ('BaseIoSize', DWORD),
                ('ControlFlags', UINT),
                ('VolumeNameLength', WORD),
                ('CriticalReservationIops', LONG64),
                ('ReservationBandwidth', LONG64),
                ('CriticalReservationBandwidth', LONG64),
                ('MaxTimePercent', LONG64),
                ('ReservationTimePercent', LONG64),
                ('CriticalReservationTimePercent', LONG64),
                ('SoftMaxIops', LONG64),
                ('SoftMaxBandwidth', LONG64),
                ('SoftMaxTimePercent', LONG64),
                ('LimitExcessNotifyIops', LONG64),
                ('LimitExcessNotifyBandwidth', LONG64),
                ('LimitExcessNotifyTimePercent', LONG64)
    ]

JOBOBJECT_IO_ATTRIBUTION_CONTROL_ENABLE = 0x1
JOBOBJECT_IO_ATTRIBUTION_CONTROL_DISABLE = 0x2
JOBOBJECT_IO_ATTRIBUTION_CONTROL_VALID_FLAGS = 0x3

class JOBOBJECT_IO_ATTRIBUTION_CONTROL_FLAGS(enum.IntFlag):
    JOBOBJECT_IO_ATTRIBUTION_CONTROL_ENABLE = 0x1
    JOBOBJECT_IO_ATTRIBUTION_CONTROL_DISABLE = 0x2
    JOBOBJECT_IO_ATTRIBUTION_CONTROL_VALID_FLAGS = 0x3

class _JOBOBJECT_IO_ATTRIBUTION_STATS(Structure):
    _fields_ = [('IoCount', ULONG_PTR),
                ('TotalNonOverlappedQueueTime', ULONGLONG),
                ('TotalNonOverlappedServiceTime', ULONGLONG),
                ('TotalSize', ULONGLONG)
    ]

JOBOBJECT_IO_ATTRIBUTION_STATS = _JOBOBJECT_IO_ATTRIBUTION_STATS
PJOBOBJECT_IO_ATTRIBUTION_STATS = POINTER(JOBOBJECT_IO_ATTRIBUTION_STATS)

class _JOBOBJECT_IO_ATTRIBUTION_INFORMATION(Structure):
    _fields_ = [('ControlFlags', DWORD),
                ('ReadStats', JOBOBJECT_IO_ATTRIBUTION_STATS),
                ('WriteStats', JOBOBJECT_IO_ATTRIBUTION_STATS)
    ]

JOBOBJECT_IO_ATTRIBUTION_INFORMATION = _JOBOBJECT_IO_ATTRIBUTION_INFORMATION
PJOBOBJECT_IO_ATTRIBUTION_INFORMATION = POINTER(JOBOBJECT_IO_ATTRIBUTION_INFORMATION)

JOB_OBJECT_TERMINATE_AT_END_OF_JOB = 0
JOB_OBJECT_POST_AT_END_OF_JOB = 1

JOB_OBJECT_MSG_END_OF_JOB_TIME = 1
JOB_OBJECT_MSG_END_OF_PROCESS_TIME = 2
JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT = 3
JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO = 4
JOB_OBJECT_MSG_NEW_PROCESS = 6
JOB_OBJECT_MSG_EXIT_PROCESS = 7
JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS = 8
JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT = 9
JOB_OBJECT_MSG_JOB_MEMORY_LIMIT = 10
JOB_OBJECT_MSG_NOTIFICATION_LIMIT = 11
JOB_OBJECT_MSG_JOB_CYCLE_TIME_LIMIT = 12
JOB_OBJECT_MSG_SILO_TERMINATED = 13

JOB_OBJECT_MSG_MINIMUM = 1
JOB_OBJECT_MSG_MAXIMUM = 12
JOB_OBJECT_VALID_COMPLETION_FILTER = ((1 << JOB_OBJECT_MSG_MAXIMUM + 1) - 1) - ((1 << JOB_OBJECT_MSG_MINIMUM) - 1)

JOB_OBJECT_LIMIT_WORKINGSET = 0x00000001
JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_AFFINITY = 0x00000010
JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x00000020
JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME = 0x00000040
JOB_OBJECT_LIMIT_SCHEDULING_CLASS = 0x00000080

JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_JOB_MEMORY_HIGH = JOB_OBJECT_LIMIT_JOB_MEMORY
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_SUBSET_AFFINITY = 0x00004000
JOB_OBJECT_LIMIT_JOB_MEMORY_LOW = 0x00008000

JOB_OBJECT_LIMIT_JOB_READ_BYTES = 0x00010000
JOB_OBJECT_LIMIT_JOB_WRITE_BYTES = 0x00020000
JOB_OBJECT_LIMIT_RATE_CONTROL = 0x00040000
JOB_OBJECT_LIMIT_CPU_RATE_CONTROL = JOB_OBJECT_LIMIT_RATE_CONTROL
JOB_OBJECT_LIMIT_IO_RATE_CONTROL = 0x00080000
JOB_OBJECT_LIMIT_NET_RATE_CONTROL = 0x00100000

JOB_OBJECT_LIMIT_RESERVED3 = 0x00008000
JOB_OBJECT_LIMIT_RESERVED4 = 0x00010000
JOB_OBJECT_LIMIT_RESERVED5 = 0x00020000
JOB_OBJECT_LIMIT_RESERVED6 = 0x00040000

JOB_OBJECT_LIMIT_VALID_FLAGS = 0x0007ffff

JOB_OBJECT_BASIC_LIMIT_VALID_FLAGS = 0x000000ff
JOB_OBJECT_EXTENDED_LIMIT_VALID_FLAGS = 0x00007fff
JOB_OBJECT_RESERVED_LIMIT_VALID_FLAGS = 0x0007ffff
JOB_OBJECT_NOTIFICATION_LIMIT_VALID_FLAGS = 0x00070204

JOB_OBJECT_UILIMIT_NONE = 0x00000000

JOB_OBJECT_UILIMIT_HANDLES = 0x00000001
JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x00000002
JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x00000004
JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008
JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x00000010
JOB_OBJECT_UILIMIT_GLOBALATOMS = 0x00000020
JOB_OBJECT_UILIMIT_DESKTOP = 0x00000040
JOB_OBJECT_UILIMIT_EXITWINDOWS = 0x00000080

JOB_OBJECT_UILIMIT_ALL = 0x000000FF

JOB_OBJECT_UI_VALID_FLAGS = 0x000000FF

JOB_OBJECT_SECURITY_NO_ADMIN = 0x00000001
JOB_OBJECT_SECURITY_RESTRICTED_TOKEN = 0x00000002
JOB_OBJECT_SECURITY_ONLY_TOKEN = 0x00000004
JOB_OBJECT_SECURITY_FILTER_TOKENS = 0x00000008

JOB_OBJECT_SECURITY_VALID_FLAGS = 0x0000000f

JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1
JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED = 0x2
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4
JOB_OBJECT_CPU_RATE_CONTROL_NOTIFY = 0x8
JOB_OBJECT_CPU_RATE_CONTROL_MIN_MAX_RATE = 0x10
JOB_OBJECT_CPU_RATE_CONTROL_VALID_FLAGS = 0x1f

JobObjectBasicAccountingInformation = 1,
JobObjectBasicLimitInformation = 2
JobObjectBasicProcessIdList = 3
JobObjectBasicUIRestrictions = 4
JobObjectSecurityLimitInformation = 5
JobObjectEndOfJobTimeInformation = 6
JobObjectAssociateCompletionPortInformation = 7
JobObjectBasicAndIoAccountingInformation = 8
JobObjectExtendedLimitInformation = 9
JobObjectJobSetInformation = 10
JobObjectGroupInformation = 11
JobObjectNotificationLimitInformation = 12
JobObjectLimitViolationInformation = 13
JobObjectGroupInformationEx = 14
JobObjectCpuRateControlInformation = 15
JobObjectCompletionFilter = 16
JobObjectCompletionCounter = 17
JobObjectReserved1Information = 18
JobObjectReserved2Information = 19
JobObjectReserved3Information = 20
JobObjectReserved4Information = 21
JobObjectReserved5Information = 22
JobObjectReserved6Information = 23
JobObjectReserved7Information = 24
JobObjectReserved8Information = 25
JobObjectReserved9Information = 26
JobObjectReserved10Information = 27
JobObjectReserved11Information = 28
JobObjectReserved12Information = 29
JobObjectReserved13Information = 30
JobObjectReserved14Information = 31
JobObjectNetRateControlInformation = 32
JobObjectNotificationLimitInformation2 = 33
JobObjectLimitViolationInformation2 = 34
JobObjectCreateSilo = 35
JobObjectSiloBasicInformation = 36
JobObjectReserved15Information = 37
JobObjectReserved16Information = 38
JobObjectReserved17Information = 39
JobObjectReserved18Information = 40
JobObjectReserved19Information = 41
JobObjectReserved20Information = 42
JobObjectReserved21Information = 43
JobObjectReserved22Information = 44
JobObjectReserved23Information = 45
JobObjectReserved24Information = 46
JobObjectReserved25Information = 47
MaxJobObjectInfoClass = 48

class _JOBOBJECTINFOCLASS(enum.IntFlag):
    JobObjectBasicAccountingInformation = 1
    JobObjectBasicLimitInformation = 2
    JobObjectBasicProcessIdList = 3
    JobObjectBasicUIRestrictions = 4
    JobObjectSecurityLimitInformation = 5
    JobObjectEndOfJobTimeInformation = 6
    JobObjectAssociateCompletionPortInformation = 7
    JobObjectBasicAndIoAccountingInformation = 8
    JobObjectExtendedLimitInformation = 9
    JobObjectJobSetInformation = 10
    JobObjectGroupInformation = 11
    JobObjectNotificationLimitInformation = 12
    JobObjectLimitViolationInformation = 13
    JobObjectGroupInformationEx = 14
    JobObjectCpuRateControlInformation = 15
    JobObjectCompletionFilter = 16
    JobObjectCompletionCounter = 17
    JobObjectReserved1Information = 18
    JobObjectReserved2Information = 19
    JobObjectReserved3Information = 20
    JobObjectReserved4Information = 21
    JobObjectReserved5Information = 22
    JobObjectReserved6Information = 23
    JobObjectReserved7Information = 24
    JobObjectReserved8Information = 25
    JobObjectReserved9Information = 26
    JobObjectReserved10Information = 27
    JobObjectReserved11Information = 28
    JobObjectReserved12Information = 29
    JobObjectReserved13Information = 30
    JobObjectReserved14Information = 31
    JobObjectNetRateControlInformation = 32
    JobObjectNotificationLimitInformation2 = 33
    JobObjectLimitViolationInformation2 = 34
    JobObjectCreateSilo = 35
    JobObjectSiloBasicInformation = 36
    JobObjectReserved15Information = 37
    JobObjectReserved16Information = 38
    JobObjectReserved17Information = 39
    JobObjectReserved18Information = 40
    JobObjectReserved19Information = 41
    JobObjectReserved20Information = 42
    JobObjectReserved21Information = 43
    JobObjectReserved22Information = 44
    JobObjectReserved23Information = 45
    JobObjectReserved24Information = 46
    JobObjectReserved25Information = 47
    MaxJobObjectInfoClass = 48

JOBOBJECTINFOCLASS = _JOBOBJECTINFOCLASS

class _SILOOBJECT_BASIC_INFORMATION(Structure):
    _fields_ = [('SiloId', DWORD),
                ('SiloParentId', DWORD),
                ('NumberOfProcesses', DWORD),
                ('IsInServerSilo', BOOLEAN),
                ('Reserved', BYTE * 3),
    ]

SILOOBJECT_BASIC_INFORMATION = _SILOOBJECT_BASIC_INFORMATION
PSILOOBJECT_BASIC_INFORMATION = POINTER(SILOOBJECT_BASIC_INFORMATION)

SERVERSILO_INITING = 0
SERVERSILO_STARTED = 1
SERVERSILO_SHUTTING_DOWN = 2
SERVERSILO_TERMINATING = 3
SERVERSILO_TERMINATED = 4

class _SERVERSILO_STATE(enum.IntFlag):
    SERVERSILO_INITING = 0
    SERVERSILO_STARTED = 1
    SERVERSILO_SHUTTING_DOWN = 2
    SERVERSILO_TERMINATING = 3
    SERVERSILO_TERMINATED = 4

SERVERSILO_STATE = _SERVERSILO_STATE
PSERVERSILO_STATE = SERVERSILO_STATE

class _SERVERSILO_BASIC_INFORMATION(Structure):
    _fields_ = [('ServiceSessionId', DWORD),
                ('State', UINT),
                ('ExitStatus', DWORD),
                ('IsDownlevelContainer', BOOLEAN),
                ('ApiSetSchema', PVOID),
                ('HostApiSetSchema', PVOID)
    ]

SERVERSILO_BASIC_INFORMATION = _SERVERSILO_BASIC_INFORMATION
PSERVERSILO_BASIC_INFORMATION = POINTER(SERVERSILO_BASIC_INFORMATION)

MEMORY_PARTITION_QUERY_ACCESS = 0x0001
MEMORY_PARTITION_MODIFY_ACCESS = 0x0002
MEMORY_PARTITION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                               SYNCHRONIZE | 
                               MEMORY_PARTITION_QUERY_ACCESS | 
                               MEMORY_PARTITION_MODIFY_ACCESS
)

FirmwareTypeUnknown = 0
FirmwareTypeBios = 1
FirmwareTypeUefi = 2
FirmwareTypeMax = 3

class _FIRMWARE_TYPE(enum.IntFlag):
    FirmwareTypeUnknown = 0
    FirmwareTypeBios = 1
    FirmwareTypeUefi = 2
    FirmwareTypeMax = 3

FIRMWARE_TYPE = _FIRMWARE_TYPE
PFIRMWARE_TYPE = FIRMWARE_TYPE

EVENT_MODIFY_STATE = 0x0002
EVENT_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
                    SYNCHRONIZE |
                    0x3
)

MUTANT_QUERY_STATE = 0x0001
MUTANT_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
                     SYNCHRONIZE | 
                     MUTANT_QUERY_STATE
)

SEMAPHORE_MODIFY_STATE = 0x0002
SEMAPHORE_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                        SYNCHRONIZE | 
                        0x3
)

TIMER_QUERY_STATE = 0x0001
TIMER_MODIFY_STATE = 0x0002

TIMER_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                    SYNCHRONIZE | 
                    TIMER_QUERY_STATE | 
                    TIMER_MODIFY_STATE
)

TIME_ZONE_ID_UNKNOWN = 0
TIME_ZONE_ID_STANDARD = 1
TIME_ZONE_ID_DAYLIGHT = 2

RelationProcessorCore = 0
RelationNumaNode = 1
RelationCache = 2
RelationProcessorPackage = 3
RelationGroup = 4
RelationProcessorDie = 5
RelationNumaNodeEx = 6
RelationProcessorModule = 7
RelationAll = 0xffff

class _LOGICAL_PROCESSOR_RELATIONSHIP(enum.IntFlag):
    RelationProcessorCore = 0
    RelationNumaNode = 1
    RelationCache = 2
    RelationProcessorPackage = 3
    RelationGroup = 4
    RelationProcessorDie = 5
    RelationNumaNodeEx = 6
    RelationProcessorModule = 7
    RelationAll = 0xffff

LOGICAL_PROCESSOR_RELATIONSHIP = _LOGICAL_PROCESSOR_RELATIONSHIP

LTP_PC_SMT = 0x1

CacheUnified = 0
CacheInstruction = 1
CacheData = 2
CacheTrace = 3

class _PROCESSOR_CACHE_TYPE(enum.IntFlag):
    CacheUnified = 0
    CacheInstruction = 1
    CacheData = 2
    CacheTrace = 3

PROCESSOR_CACHE_TYPE = _PROCESSOR_CACHE_TYPE

CACHE_FULLY_ASSOCIATIVE = 0xFF

class _CACHE_DESCRIPTOR(Structure):
    _fields_ = [('Level', BYTE),
                ('Associativity', BYTE),
                ('LineSize', WORD),
                ('Size', DWORD),
                ('Type', UINT),
    ]

CACHE_DESCRIPTOR = _CACHE_DESCRIPTOR
PCACHE_DESCRIPTOR = POINTER(CACHE_DESCRIPTOR)

class _SYSTEM_LOGICAL_PROCESSOR_INFORMATION(Structure):
    class DUMMYUNIONNAME(Union):
        class ProcessorCore(Structure):
            _fields_ = [('Flags', BYTE)]
        
        class NumaNode(Structure):
            _fields_ = [('NodeNumber', DWORD)]
        
        _anonymous_ = ['ProcessorCore', 'NumaNode']
        _fields_ = [('Cache', CACHE_DESCRIPTOR),
                    ('Reserved', ULONGLONG * 2),
                    ('ProcessorCore', ProcessorCore),
                    ('NumaNode', NumaNode)
        ]
    
    _fields_ = [('ProcessorMask', ULONG_PTR),
                ('Relationship', UINT),
                ('DUMMYUNIONNAME', DUMMYUNIONNAME)
    ]

SYSTEM_LOGICAL_PROCESSOR_INFORMATION = _SYSTEM_LOGICAL_PROCESSOR_INFORMATION
PSYSTEM_LOGICAL_PROCESSOR_INFORMATION = POINTER(SYSTEM_LOGICAL_PROCESSOR_INFORMATION)

class _PROCESSOR_RELATIONSHIP(Structure):
    _fields_ = [('Flags', BYTE),
                ('EfficiencyClass', BYTE),
                ('Reserved', BYTE * 20),
                ('GroupCount', WORD),
                ('GroupMask', GROUP_AFFINITY * ANYSIZE_ARRAY)
    ]

PROCESSOR_RELATIONSHIP = _PROCESSOR_RELATIONSHIP
PPROCESSOR_RELATIONSHIP = POINTER(PROCESSOR_RELATIONSHIP)

class _NUMA_NODE_RELATIONSHIP(Structure):
    _fields_ = [('NodeNumber', DWORD),
                ('Reserved', BYTE * 20),
                ('GroupMask', GROUP_AFFINITY)
    ]

NUMA_NODE_RELATIONSHIP = _NUMA_NODE_RELATIONSHIP
PNUMA_NODE_RELATIONSHIP = POINTER(NUMA_NODE_RELATIONSHIP)

class _CACHE_RELATIONSHIP(Structure):
    _fields_ = [('Level', BYTE),
                ('Associativity', BYTE),
                ('LineSize', WORD),
                ('CacheSize', DWORD),
                ('Type', UINT),
                ('Reserved', BYTE * 20),
                ('GroupMask', GROUP_AFFINITY)
    ]

CACHE_RELATIONSHIP = _CACHE_RELATIONSHIP
CACHE_RELATIONSHIP = POINTER(CACHE_RELATIONSHIP)

class _PROCESSOR_GROUP_INFO(Structure):
    _fields_ = [('MaximumProcessorCount', BYTE),
                ('ActiveProcessorCount', BYTE),
                ('Reserved', BYTE * 38),
                ('ActiveProcessorMask', KAFFINITY)
    ]

PROCESSOR_GROUP_INFO = _PROCESSOR_GROUP_INFO
PPROCESSOR_GROUP_INFO = POINTER(PROCESSOR_GROUP_INFO)

class _GROUP_RELATIONSHIP(Structure):
    _fields_ = [('MaximumGroupCount', WORD),
                ('ActiveGroupCount', WORD),
                ('Reserved', BYTE * 20),
                ('GroupInfo', PROCESSOR_GROUP_INFO * ANYSIZE_ARRAY)
    ]

GROUP_RELATIONSHIP = _GROUP_RELATIONSHIP
PGROUP_RELATIONSHIP = POINTER(GROUP_RELATIONSHIP)

class _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX(Structure):
    class ProNumCacGroUnion(Union):
        _fields_ = [('Processor', PROCESSOR_RELATIONSHIP),
                    ('NumaNode', NUMA_NODE_RELATIONSHIP),
                    ('Cache', CACHE_RELATIONSHIP),
                    ('Group', GROUP_RELATIONSHIP)
        ]

    _anonymous_ = ['ProNumCacGroUnion']
    _fields_ = [('Relationship', UINT),
                ('Size', DWORD),
                ('ProNumCacGroUnion', ProNumCacGroUnion)
    ]

SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX = _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX = POINTER(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)

CpuSetInformation = 0

class _CPU_SET_INFORMATION_TYPE(enum.IntFlag):
    CpuSetInformation = 0

CPU_SET_INFORMATION_TYPE = _CPU_SET_INFORMATION_TYPE
PCPU_SET_INFORMATION_TYPE = CPU_SET_INFORMATION_TYPE

SYSTEM_CPU_SET_INFORMATION_PARKED = 0x1
SYSTEM_CPU_SET_INFORMATION_ALLOCATED = 0x2
SYSTEM_CPU_SET_INFORMATION_ALLOCATED_TO_TARGET_PROCESS = 0x4
SYSTEM_CPU_SET_INFORMATION_REALTIME = 0x8

class _SYSTEM_CPU_SET_INFORMATION(Structure):
    class DUMMYUNIONNAME(Union):
        class CpuSet(Structure):
            class DUMMYUNIONNAME2(Union):
                class ParAllReaResLittleStruct(LittleEndianStructure):
                    _fields_ = [('Parked', BYTE, 1),
                                ('Allocated', BYTE, 1),
                                ('AllocatedToTargetProcess', BYTE, 1),
                                ('RealTime', BYTE, 1),
                                ('ReservedFlags', BYTE, 4)
                    ]

                _anonymous_ = ['ParAllReaResLittleStruct']
                _fields_ = [('AllFlags', BYTE),
                            ('ParAllReaResLittleStruct', ParAllReaResLittleStruct)
                ]
            
            class DUMMYUNIONNAME3(Union):
                _fields_ = [('Reserved', DWORD),
                            ('SchedulingClass', BYTE)
                ]
            
            _anonymous_ = ['DUMMYUNIONNAME2', 'DUMMYUNIONNAME3']
            _fields_ = [('Id', DWORD),
                        ('Group', WORD),
                        ('LogicalProcessorIndex', BYTE),
                        ('CoreIndex', BYTE),
                        ('LastLevelCacheIndex', BYTE),
                        ('NumaNodeIndex', BYTE),
                        ('EfficiencyClass', BYTE),
                        ('DUMMYUNIONNAME2', DUMMYUNIONNAME2),
                        ('DUMMYUNIONNAME3', DUMMYUNIONNAME3),
                        ('AllocationTag', DWORD64)
            ]
        
        _anonymous_ = ['CpuSet']
        _fields_ = [('CpuSet', CpuSet)]

    _anonymous_ = ['DUMMYUNIONNAME']
    _fields_ = [('Size', DWORD),
                ('Type', UINT),
                ('DUMMYUNIONNAME', DUMMYUNIONNAME)
    ]

SYSTEM_CPU_SET_INFORMATION = _SYSTEM_CPU_SET_INFORMATION
PSYSTEM_CPU_SET_INFORMATION = POINTER(SYSTEM_CPU_SET_INFORMATION)

class _SYSTEM_POOL_ZEROING_INFORMATION(Structure):
    _fields_ = [('CycleTime', DWORD64)]

SYSTEM_POOL_ZEROING_INFORMATION = _SYSTEM_POOL_ZEROING_INFORMATION
PSYSTEM_POOL_ZEROING_INFORMATION = POINTER(SYSTEM_POOL_ZEROING_INFORMATION)

class _SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION(Structure):
    _fields_ = [('CycleTime', DWORD64)]

SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION = _SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION
PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION = POINTER(SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION)

class _SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION(LittleEndianStructure):
    _fields_ = [('Machine', DWORD, 16),
                ('KernelMode', DWORD, 1),
                ('UserMode', DWORD, 1),
                ('Native', DWORD, 1),
                ('Process', DWORD, 1),
                ('WoW64Container', DWORD, 1),
                ('ReservedZero0', DWORD, 11)
    ]

SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION = _SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION
PSYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION = POINTER(SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION)

PROCESSOR_INTEL_386 = 386
PROCESSOR_INTEL_486 = 486
PROCESSOR_INTEL_PENTIUM = 586
PROCESSOR_INTEL_IA64 = 2200
PROCESSOR_AMD_X8664 = 8664
PROCESSOR_MIPS_R4000 = 4000
PROCESSOR_ALPHA_21064 = 21064
PROCESSOR_PPC_601 = 601
PROCESSOR_PPC_603 = 603
PROCESSOR_PPC_604 = 604
PROCESSOR_PPC_620 = 620
PROCESSOR_HITACHI_SH3 = 10003
PROCESSOR_HITACHI_SH3E = 10004
PROCESSOR_HITACHI_SH4 = 10005
PROCESSOR_MOTOROLA_821 = 821
PROCESSOR_SHx_SH3 = 103
PROCESSOR_SHx_SH4 = 104
PROCESSOR_STRONGARM = 2577
PROCESSOR_ARM720 = 1824
PROCESSOR_ARM820 = 2080
PROCESSOR_ARM920 = 2336
PROCESSOR_ARM_7TDMI = 70001
PROCESSOR_OPTIL = 0x494f

PROCESSOR_ARCHITECTURE_INTEL = 0
PROCESSOR_ARCHITECTURE_MIPS = 1
PROCESSOR_ARCHITECTURE_ALPHA = 2
PROCESSOR_ARCHITECTURE_PPC = 3
PROCESSOR_ARCHITECTURE_SHX = 4
PROCESSOR_ARCHITECTURE_ARM = 5
PROCESSOR_ARCHITECTURE_IA64 = 6
PROCESSOR_ARCHITECTURE_ALPHA64 = 7
PROCESSOR_ARCHITECTURE_MSIL = 8
PROCESSOR_ARCHITECTURE_AMD64 = 9
PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 = 10
PROCESSOR_ARCHITECTURE_NEUTRAL = 11
PROCESSOR_ARCHITECTURE_ARM64 = 12
PROCESSOR_ARCHITECTURE_ARM32_ON_WIN64 = 13
PROCESSOR_ARCHITECTURE_IA32_ON_ARM64 = 14

PROCESSOR_ARCHITECTURE_UNKNOWN = 0xffff

PF_FLOATING_POINT_PRECISION_ERRATA = 0
PF_FLOATING_POINT_EMULATED = 1
PF_COMPARE_EXCHANGE_DOUBLE = 2
PF_MMX_INSTRUCTIONS_AVAILABLE = 3
PF_PPC_MOVEMEM_64BIT_OK = 4
PF_ALPHA_BYTE_INSTRUCTIONS = 5
PF_XMMI_INSTRUCTIONS_AVAILABLE = 6
PF_3DNOW_INSTRUCTIONS_AVAILABLE = 7
PF_RDTSC_INSTRUCTION_AVAILABLE = 8
PF_PAE_ENABLED = 9
PF_XMMI64_INSTRUCTIONS_AVAILABLE = 10
PF_SSE_DAZ_MODE_AVAILABLE = 11
PF_NX_ENABLED = 12
PF_SSE3_INSTRUCTIONS_AVAILABLE = 13
PF_COMPARE_EXCHANGE128 = 14
PF_COMPARE64_EXCHANGE128 = 15
PF_CHANNELS_ENABLED = 16
PF_XSAVE_ENABLED = 17
PF_ARM_VFP_32_REGISTERS_AVAILABLE = 18
PF_ARM_NEON_INSTRUCTIONS_AVAILABLE = 19
PF_SECOND_LEVEL_ADDRESS_TRANSLATION = 20
PF_VIRT_FIRMWARE_ENABLED = 21
PF_RDWRFSGSBASE_AVAILABLE = 22
PF_FASTFAIL_AVAILABLE = 23
PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE = 24
PF_ARM_64BIT_LOADSTORE_ATOMIC = 25
PF_ARM_EXTERNAL_CACHE_AVAILABLE = 26
PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE = 27
PF_RDRAND_INSTRUCTION_AVAILABLE = 28
PF_ARM_V8_INSTRUCTIONS_AVAILABLE = 29
PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE = 30
PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE = 31
PF_RDTSCP_INSTRUCTION_AVAILABLE = 32
PF_RDPID_INSTRUCTION_AVAILABLE = 33
PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE = 34
PF_MONITORX_INSTRUCTION_AVAILABLE = 35
PF_SSSE3_INSTRUCTIONS_AVAILABLE = 36
PF_SSE4_1_INSTRUCTIONS_AVAILABLE = 37
PF_SSE4_2_INSTRUCTIONS_AVAILABLE = 38
PF_AVX_INSTRUCTIONS_AVAILABLE = 39
PF_AVX2_INSTRUCTIONS_AVAILABLE = 40
PF_AVX512F_INSTRUCTIONS_AVAILABLE = 41
PF_ERMS_AVAILABLE = 42
PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE = 43
PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE = 44
PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE = 45

XSTATE_LEGACY_FLOATING_POINT = 0
XSTATE_LEGACY_SSE = 1
XSTATE_GSSE = 2
XSTATE_AVX = XSTATE_GSSE
XSTATE_MPX_BNDREGS = 3
XSTATE_MPX_BNDCSR = 4
XSTATE_AVX512_KMASK = 5
XSTATE_AVX512_ZMM_H = 6
XSTATE_AVX512_ZMM = 7
XSTATE_IPT = 8
XSTATE_PASID = 10
XSTATE_CET_U = 11
XSTATE_CET_S = 12
XSTATE_AMX_TILE_CONFIG = 17
XSTATE_AMX_TILE_DATA = 18
XSTATE_LWP = 62
MAXIMUM_XSTATE_FEATURES = 64

XSTATE_MASK_LEGACY_FLOATING_POINT = (1 << XSTATE_LEGACY_FLOATING_POINT)
XSTATE_MASK_LEGACY_SSE = (1 << XSTATE_LEGACY_SSE)
XSTATE_MASK_LEGACY = (XSTATE_MASK_LEGACY_FLOATING_POINT | 
                      XSTATE_MASK_LEGACY_SSE
)

XSTATE_MASK_GSSE = (1 << XSTATE_GSSE)
XSTATE_MASK_AVX = (XSTATE_MASK_GSSE)
XSTATE_MASK_MPX = ((1 << XSTATE_MPX_BNDREGS) | 
                   (1 << XSTATE_MPX_BNDCSR)
)

XSTATE_MASK_AVX512 = ((1 << XSTATE_AVX512_KMASK) | 
                      (1 << XSTATE_AVX512_ZMM_H) | 
                      (1 << XSTATE_AVX512_ZMM)
)

XSTATE_MASK_IPT = (1 << XSTATE_IPT)
XSTATE_MASK_PASID = (1 << XSTATE_PASID)
XSTATE_MASK_CET_U = (1 << XSTATE_CET_U)
XSTATE_MASK_CET_S = (1 << XSTATE_CET_S)
XSTATE_MASK_AMX_TILE_CONFIG = (1 << XSTATE_AMX_TILE_CONFIG)
XSTATE_MASK_AMX_TILE_DATA = (1 << XSTATE_AMX_TILE_DATA)
XSTATE_MASK_LWP = (1 << XSTATE_LWP)

if platform.machine().lower() in ['amd64', 'x86_64']:
    XSTATE_MASK_ALLOWED = (XSTATE_MASK_LEGACY | 
                           XSTATE_MASK_AVX | 
                           XSTATE_MASK_MPX | 
                           XSTATE_MASK_AVX512 | 
                           XSTATE_MASK_IPT | 
                           XSTATE_MASK_PASID | 
                           XSTATE_MASK_CET_U | 
                           XSTATE_MASK_AMX_TILE_CONFIG | 
                           XSTATE_MASK_AMX_TILE_DATA | 
                           XSTATE_MASK_LWP
    )
elif platform.machine().lower() in ['x86', 'i386']:
    XSTATE_MASK_ALLOWED = (XSTATE_MASK_LEGACY | 
                           XSTATE_MASK_AVX | 
                           XSTATE_MASK_MPX | 
                           XSTATE_MASK_AVX512 | 
                           XSTATE_MASK_IPT | 
                           XSTATE_MASK_CET_U | 
                           XSTATE_MASK_LWP
    )

XSTATE_MASK_PERSISTENT = ((1 << XSTATE_MPX_BNDCSR) | XSTATE_MASK_LWP)
XSTATE_MASK_USER_VISIBLE_SUPERVISOR = XSTATE_MASK_CET_U
XSTATE_MASK_LARGE_FEATURES = XSTATE_MASK_AMX_TILE_DATA

XSTATE_COMPACTION_ENABLE = 63
XSTATE_COMPACTION_ENABLE_MASK = (1 << XSTATE_COMPACTION_ENABLE)

XSTATE_ALIGN_BIT = 1
XSTATE_ALIGN_MASK = (1 << XSTATE_ALIGN_BIT)

XSTATE_XFD_BIT = 2
XSTATE_XFD_MASK = (1 << XSTATE_XFD_BIT)

XSTATE_CONTROLFLAG_XSAVEOPT_MASK = 1
XSTATE_CONTROLFLAG_XSAVEC_MASK = 2
XSTATE_CONTROLFLAG_XFD_MASK = 4
XSTATE_CONTROLFLAG_VALID_MASK = (XSTATE_CONTROLFLAG_XSAVEOPT_MASK | 
                                 XSTATE_CONTROLFLAG_XSAVEC_MASK | 
                                 XSTATE_CONTROLFLAG_XFD_MASK
)

class _XSTATE_FEATURE(Structure):
    _fields_ = [('Offset', DWORD),
                ('Size', DWORD)
    ]

XSTATE_FEATURE = _XSTATE_FEATURE
PXSTATE_FEATURE = POINTER(XSTATE_FEATURE)

class _XSTATE_CONFIGURATION(Structure):
    class ControlFlagsUnion(Union):
        class OptComExtLittleStruct(Structure):
            _fields_ = [('OptimizedSave', DWORD, 1),
                        ('CompactionEnabled', DWORD, 1),
                        ('ExtendedFeatureDisable', DWORD, 1)
            ]
        
        _anonymous_ = ['OptComExtLittleStruct']
        _fields_ = [('ControlFlags', DWORD),
                    ('OptComExtLittleStruct', OptComExtLittleStruct)
        ]
    
    _anonymous_ = ['ControlFlagsUnion']
    _fields_ = [('EnabledFeatures', DWORD64),
                ('EnabledVolatileFeatures', DWORD64),
                ('Size', DWORD),
                ('ControlFlagsUnion', ControlFlagsUnion),
                ('Features', XSTATE_FEATURE),
                ('EnabledSupervisorFeatures', DWORD64),
                ('AlignedFeatures', DWORD64),
                ('AllFeatureSize', DWORD),
                ('AllFeatures', DWORD),
                ('EnabledUserVisibleSupervisorFeatures', DWORD64),
                ('ExtendedFeatureDisableFeatures', DWORD64),
                ('AllNonLargeFeatureSize', DWORD),
                ('Spare', DWORD)
    ]

XSTATE_CONFIGURATION = _XSTATE_CONFIGURATION
PXSTATE_CONFIGURATION = POINTER(XSTATE_CONFIGURATION)

class _MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [('BaseAddress', PVOID),
                ('AllocationBase', PVOID),
                ('AllocationProtect', DWORD),
                ('RegionSize', SIZE_T),
                ('State', DWORD),
                ('Protect', DWORD),
                ('Type', DWORD)
    ]

    if platform.machine().lower() == 'amd64' and sys.maxsize > 2 ** 32:
        _fields_.append(('PartitionId', WORD))

MEMORY_BASIC_INFORMATION = _MEMORY_BASIC_INFORMATION
PMEMORY_BASIC_INFORMATION = POINTER(MEMORY_BASIC_INFORMATION)

class _MEMORY_BASIC_INFORMATION32(Structure):
    _fields_ = [('BaseAddress', DWORD),
                ('AllocationBase', DWORD),
                ('AllocationProtect', DWORD),
                ('RegionSize', DWORD),
                ('State', DWORD),
                ('Protect', DWORD),
                ('Type', DWORD)
    ]

MEMORY_BASIC_INFORMATION32 = _MEMORY_BASIC_INFORMATION32
PMEMORY_BASIC_INFORMATION32 = POINTER(MEMORY_BASIC_INFORMATION32)

class _MEMORY_BASIC_INFORMATION64(Structure):
    _align_ = 16
    _fields_ = [('BaseAddress', ULONGLONG),
                ('AllocationBase', ULONGLONG),
                ('AllocationProtect', DWORD),
                ('__alignment1', DWORD),
                ('RegionSize', ULONGLONG),
                ('State', DWORD),
                ('Protect', DWORD),
                ('Type', DWORD),
                ('__alignment2', DWORD)
    ]

MEMORY_BASIC_INFORMATION64 = _MEMORY_BASIC_INFORMATION64
PMEMORY_BASIC_INFORMATION64 = POINTER(MEMORY_BASIC_INFORMATION64)

CFG_CALL_TARGET_VALID = 0x01
CFG_CALL_TARGET_PROCESSED = 0x02
CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID = 0x04
CFG_CALL_TARGET_VALID_XFG = 0x08
CFG_CALL_TARGET_CONVERT_XFG_TO_CFG = 0x10

class _CFG_CALL_TARGET_INFO(Structure):
    _fields_ = [('Offset', ULONG_PTR),
                ('Flags', ULONG_PTR)
    ]

CFG_CALL_TARGET_INFO = _CFG_CALL_TARGET_INFO
PCFG_CALL_TARGET_INFO = POINTER(CFG_CALL_TARGET_INFO)

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

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400
PAGE_GRAPHICS_NOACCESS = 0x0800
PAGE_GRAPHICS_READONLY = 0x1000
PAGE_GRAPHICS_READWRITE = 0x2000
PAGE_GRAPHICS_EXECUTE = 0x4000
PAGE_GRAPHICS_EXECUTE_READ = 0x8000
PAGE_GRAPHICS_EXECUTE_READWRITE = 0x10000
PAGE_GRAPHICS_COHERENT = 0x20000
PAGE_GRAPHICS_NOCACHE = 0x40000
PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000
PAGE_REVERT_TO_FILE_MAP = 0x80000000
PAGE_TARGETS_NO_UPDATE = 0x40000000
PAGE_TARGETS_INVALID = 0x40000000
PAGE_ENCLAVE_UNVALIDATED = 0x20000000
PAGE_ENCLAVE_MASK = 0x10000000
PAGE_ENCLAVE_DECOMMIT = (PAGE_ENCLAVE_MASK | 0)
PAGE_ENCLAVE_SS_FIRST = (PAGE_ENCLAVE_MASK | 1)
PAGE_ENCLAVE_SS_REST = (PAGE_ENCLAVE_MASK | 2)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_REPLACE_PLACEHOLDER = 0x4000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_FREE = 0x10000
MEM_PRIVATE = 0x20000
MEM_RESERVE_PLACEHOLDER = 0x40000
MEM_MAPPED = 0x40000
MEM_RESET = 0x80000
MEM_TOP_DOWN = 0x100000
MEM_WRITE_WATCH = 0x200000
MEM_PHYSICAL = 0x400000
MEM_ROTATE = 0x800000
MEM_DIFFERENT_IMAGE_BASE_OK = 0x800000
MEM_RESET_UNDO = 0x1000000
MEM_LARGE_PAGES = 0x20000000
MEM_4MB_PAGES = 0x80000000
MEM_64K_PAGES = (MEM_LARGE_PAGES | MEM_PHYSICAL)
MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001
MEM_COALESCE_PLACEHOLDERS = 0x00000001
MEM_PRESERVE_PLACEHOLDER = 0x00000002

class _MEM_ADDRESS_REQUIREMENTS(Structure):
    _fields_ = [('LowestStartingAddress', PVOID),
                ('HighestEndingAddress', PVOID),
                ('Alignment', SIZE_T),
    ]

MEM_ADDRESS_REQUIREMENTS = _MEM_ADDRESS_REQUIREMENTS
PMEM_ADDRESS_REQUIREMENTS = POINTER(MEM_ADDRESS_REQUIREMENTS)

MEM_EXTENDED_PARAMETER_GRAPHICS = 0x01
MEM_EXTENDED_PARAMETER_NONPAGED = 0x02
MEM_EXTENDED_PARAMETER_ZERO_PAGES_OPTIONAL = 0x04
MEM_EXTENDED_PARAMETER_NONPAGED_LARGE = 0x08
MEM_EXTENDED_PARAMETER_NONPAGED_HUGE = 0x10
MEM_EXTENDED_PARAMETER_SOFT_FAULT_PAGES = 0x20
MEM_EXTENDED_PARAMETER_EC_CODE = 0x40
MEM_EXTENDED_PARAMETER_IMAGE_NO_HPAT = 0x80

# from basetsd.h
MAXULONG64 = 18446744073709551615
MAXLONG64 = 9223372036854775807
MINLONG64 = -9223372036854775808

MEM_EXTENDED_PARAMETER_NUMA_NODE_MANDATORY = MINLONG64

MemExtendedParameterInvalidType = 0
MemExtendedParameterAddressRequirements = 1
MemExtendedParameterNumaNode = 2
MemExtendedParameterPartitionHandle = 3
MemExtendedParameterUserPhysicalHandle = 4
MemExtendedParameterAttributeFlags = 5
MemExtendedParameterImageMachine = 6
MemExtendedParameterMax = 7

class MEM_EXTENDED_PARAMETER_TYPE(enum.IntFlag):
    MemExtendedParameterInvalidType = 0
    MemExtendedParameterAddressRequirements = 1
    MemExtendedParameterNumaNode = 2
    MemExtendedParameterPartitionHandle = 3
    MemExtendedParameterUserPhysicalHandle = 4
    MemExtendedParameterAttributeFlags = 5
    MemExtendedParameterImageMachine = 6
    MemExtendedParameterMax = 7

PMEM_EXTENDED_PARAMETER_TYPE = MEM_EXTENDED_PARAMETER_TYPE

MEM_EXTENDED_PARAMETER_TYPE_BITS = 8

class MEM_EXTENDED_PARAMETER(Structure):
    _align_ = 8

    class TyResLittleStruct(LittleEndianStructure):
        _fields_ = [('Type', DWORD64, MEM_EXTENDED_PARAMETER_TYPE_BITS),
                    ('Reserved', DWORD64, 64 - MEM_EXTENDED_PARAMETER_TYPE_BITS)
        ]

    class UPoSiHaUnion(Union):
        _fields_ = [('ULong64', DWORD64),
                    ('Pointer', PVOID),
                    ('Size', SIZE_T),
                    ('Handle', HANDLE),
                    ('ULong', DWORD)
        ]

    _anonymous_ = ['TyResLittleStruct', 'UPoSiHaUnion']
    _fields_ = [('TyResLittleStruct', TyResLittleStruct),
                ('UPoSiHaUnion', UPoSiHaUnion)
    ]

PMEM_EXTENDED_PARAMETER = POINTER(MEM_EXTENDED_PARAMETER)

MEMORY_CURRENT_PARTITION_HANDLE = HANDLE(LONG_PTR(-1).value).value
MEMORY_SYSTEM_PARTITION_HANDLE = HANDLE(LONG_PTR(-2).value).value
MEMORY_EXISTING_VAD_PARTITION_HANDLE = HANDLE(LONG_PTR(-3).value).value
MEM_DEDICATED_ATTRIBUTE_NOT_SPECIFIED = DWORD64(-1).value

MemDedicatedAttributeReadBandwidth = 0
MemDedicatedAttributeReadLatency = 1
MemDedicatedAttributeWriteBandwidth = 2
MemDedicatedAttributeWriteLatency = 3
MemDedicatedAttributeMax = 4

class _MEM_DEDICATED_ATTRIBUTE_TYPE(enum.IntFlag):
    MemDedicatedAttributeReadBandwidth = 0
    MemDedicatedAttributeReadLatency = 1
    MemDedicatedAttributeWriteBandwidth = 2
    MemDedicatedAttributeWriteLatency = 3
    MemDedicatedAttributeMax = 4

MEM_DEDICATED_ATTRIBUTE_TYPE = _MEM_DEDICATED_ATTRIBUTE_TYPE
PMEM_DEDICATED_ATTRIBUTE_TYPE = MEM_DEDICATED_ATTRIBUTE_TYPE

SEC_HUGE_PAGES = 0x20000
SEC_PARTITION_OWNER_HANDLE = 0x40000
SEC_64K_PAGES = 0x80000
SEC_FILE = 0x800000
SEC_IMAGE = 0x1000000
SEC_PROTECTED_IMAGE = 0x2000000
SEC_RESERVE = 0x4000000
SEC_COMMIT = 0x8000000
SEC_NOCACHE = 0x10000000
SEC_WRITECOMBINE = 0x40000000
SEC_LARGE_PAGES = 0x80000000
SEC_IMAGE_NO_EXECUTE = (SEC_IMAGE | SEC_NOCACHE)

MemSectionExtendedParameterInvalidType = 0
MemSectionExtendedParameterUserPhysicalFlags = 1
MemSectionExtendedParameterNumaNode = 2
MemSectionExtendedParameterSigningLevel = 3
MemSectionExtendedParameterMax = 4

class MEM_SECTION_EXTENDED_PARAMETER_TYPE(enum.IntFlag):
    MemSectionExtendedParameterInvalidType = 0
    MemSectionExtendedParameterUserPhysicalFlags = 1
    MemSectionExtendedParameterNumaNode = 2
    MemSectionExtendedParameterSigningLevel = 3
    MemSectionExtendedParameterMax = 4

PMEM_SECTION_EXTENDED_PARAMETER_TYPE = MEM_SECTION_EXTENDED_PARAMETER_TYPE

MEM_IMAGE = SEC_IMAGE
WRITE_WATCH_FLAG_RESET = 0x01

ENCLAVE_TYPE_SGX = 0x00000001
ENCLAVE_TYPE_SGX2 = 0x00000002

class _ENCLAVE_CREATE_INFO_SGX(Structure):
    _fields_ = [('Secs', BYTE * 4096)]

ENCLAVE_CREATE_INFO_SGX = _ENCLAVE_CREATE_INFO_SGX
PENCLAVE_CREATE_INFO_SGX = POINTER(ENCLAVE_CREATE_INFO_SGX)

class _ENCLAVE_INIT_INFO_SGX(Structure):
    _fields_ = [('SigStruct', BYTE * 1808),
                ('Reserved1', BYTE * 240),
                ('EInitToken', BYTE * 304),
                ('Reserved2', BYTE * 1744),
    ]

ENCLAVE_INIT_INFO_SGX = _ENCLAVE_INIT_INFO_SGX
PENCLAVE_INIT_INFO_SGX = POINTER(ENCLAVE_INIT_INFO_SGX)

ENCLAVE_TYPE_VBS = 0x00000010

class _ENCLAVE_CREATE_INFO_VBS(Structure):
    _fields_ = [('Flags', DWORD),
                ('OwnerID', BYTE * 32)
    ]

ENCLAVE_CREATE_INFO_VBS = _ENCLAVE_CREATE_INFO_VBS
PENCLAVE_CREATE_INFO_VBS = POINTER(ENCLAVE_CREATE_INFO_VBS)

ENCLAVE_VBS_FLAG_DEBUG = 0x00000001

ENCLAVE_TYPE_VBS_BASIC = 0x00000011

class _ENCLAVE_CREATE_INFO_VBS_BASIC(Structure):
    _fields_ = [('Flags', DWORD),
                ('OwnerID', BYTE * 32)
    ]

ENCLAVE_CREATE_INFO_VBS_BASIC = _ENCLAVE_CREATE_INFO_VBS_BASIC
PENCLAVE_CREATE_INFO_VBS_BASIC = POINTER(ENCLAVE_CREATE_INFO_VBS_BASIC)

class _ENCLAVE_LOAD_DATA_VBS_BASIC(Structure):
    _fields_ = [('PageType', DWORD)]

ENCLAVE_LOAD_DATA_VBS_BASIC = _ENCLAVE_LOAD_DATA_VBS_BASIC
PENCLAVE_LOAD_DATA_VBS_BASIC = POINTER(ENCLAVE_LOAD_DATA_VBS_BASIC)

VBS_BASIC_PAGE_MEASURED_DATA = 0x00000001
VBS_BASIC_PAGE_UNMEASURED_DATA = 0x00000002
VBS_BASIC_PAGE_ZERO_FILL = 0x00000003
VBS_BASIC_PAGE_THREAD_DESCRIPTOR = 0x00000004
VBS_BASIC_PAGE_SYSTEM_CALL = 0x00000005

class _ENCLAVE_INIT_INFO_VBS_BASIC(Structure):
    class SigUnUnion(Union):
        _fields_ = [('SignatureInfoHandle', HANDLE),
                    ('Unused', ULONGLONG)
        ]

    _anonymous_ = ['SigUnUnion']
    _fields_ = [('FamilyId', BYTE * ENCLAVE_SHORT_ID_LENGTH),
                ('ImageId', BYTE * ENCLAVE_SHORT_ID_LENGTH),
                ('EnclaveSize', ULONGLONG),
                ('EnclaveSvn', DWORD),
                ('Reserved', DWORD),
                ('SigUnUnion', SigUnUnion)
    ]

ENCLAVE_INIT_INFO_VBS_BASIC = _ENCLAVE_INIT_INFO_VBS_BASIC
PENCLAVE_INIT_INFO_VBS_BASIC = POINTER(ENCLAVE_INIT_INFO_VBS_BASIC)

class _ENCLAVE_INIT_INFO_VBS(Structure):
    _fields_ = [('Length', DWORD),
                ('ThreadCount', DWORD)
    ]

ENCLAVE_INIT_INFO_VBS = _ENCLAVE_INIT_INFO_VBS
PENCLAVE_INIT_INFO_VBS = POINTER(ENCLAVE_INIT_INFO_VBS)

DEDICATED_MEMORY_CACHE_ELIGIBLE = 0x1

class _MEMORY_PARTITION_DEDICATED_MEMORY_ATTRIBUTE(Structure):
    _align_ = 8
    _fields_ = [('Type', UINT),
                ('Reserved', DWORD),
                ('Value', DWORD64)
    ]

MEMORY_PARTITION_DEDICATED_MEMORY_ATTRIBUTE = _MEMORY_PARTITION_DEDICATED_MEMORY_ATTRIBUTE
PMEMORY_PARTITION_DEDICATED_MEMORY_ATTRIBUTE = POINTER(MEMORY_PARTITION_DEDICATED_MEMORY_ATTRIBUTE)

class _MEMORY_PARTITION_DEDICATED_MEMORY_INFORMATION(Structure):
    _align_ = 8
    _fields_ = [('NextEntryOffset', DWORD),
                ('SizeOfInformation', DWORD),
                ('Flags', DWORD),
                ('AttributesOffset', DWORD),
                ('AttributeCount', DWORD),
                ('Reserved', DWORD),
                ('TypeId', DWORD64)
    ]

MEMORY_PARTITION_DEDICATED_MEMORY_INFORMATION = _MEMORY_PARTITION_DEDICATED_MEMORY_INFORMATION
PMEMORY_PARTITION_DEDICATED_MEMORY_INFORMATION = POINTER(MEMORY_PARTITION_DEDICATED_MEMORY_INFORMATION)

FILE_READ_DATA = 0x0001
FILE_LIST_DIRECTORY = 0x0001

FILE_WRITE_DATA = 0x0002
FILE_ADD_FILE = 0x0002

FILE_APPEND_DATA = 0x0004
FILE_ADD_SUBDIRECTORY = 0x0004
FILE_CREATE_PIPE_INSTANCE = 0x0004

FILE_READ_EA = 0x0008
FILE_WRITE_EA = 0x0010
FILE_EXECUTE = 0x0020
FILE_TRAVERSE = 0x0020
FILE_DELETE_CHILD = 0x0040
FILE_READ_ATTRIBUTES = 0x0080
FILE_WRITE_ATTRIBUTES = 0x0100

FILE_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                   SYNCHRONIZE | 
                   0x1FF
)

FILE_GENERIC_READ = (STANDARD_RIGHTS_READ | 
                     FILE_READ_DATA | 
                     FILE_READ_ATTRIBUTES | 
                     FILE_READ_EA | 
                     SYNCHRONIZE
)

FILE_GENERIC_WRITE = (STANDARD_RIGHTS_WRITE | 
                      FILE_WRITE_DATA | 
                      FILE_WRITE_ATTRIBUTES | 
                      FILE_WRITE_EA | 
                      FILE_APPEND_DATA | 
                      SYNCHRONIZE
)

FILE_GENERIC_EXECUTE = (STANDARD_RIGHTS_EXECUTE | 
                        FILE_READ_ATTRIBUTES | 
                        FILE_EXECUTE | 
                        SYNCHRONIZE
)

FILE_SUPERSEDE =                    0x00000000
FILE_OPEN =                         0x00000001
FILE_CREATE =                       0x00000002
FILE_OPEN_IF =                      0x00000003
FILE_OVERWRITE =                    0x00000004
FILE_OVERWRITE_IF =                 0x00000005
FILE_MAXIMUM_DISPOSITION =          0x00000005

FILE_DIRECTORY_FILE =               0x00000001
FILE_WRITE_THROUGH =                0x00000002
FILE_SEQUENTIAL_ONLY =              0x00000004
FILE_NO_INTERMEDIATE_BUFFERING =    0x00000008
FILE_SYNCHRONOUS_IO_ALERT =         0x00000010
FILE_SYNCHRONOUS_IO_NONALERT =      0x00000020
FILE_NON_DIRECTORY_FILE =           0x00000040
FILE_CREATE_TREE_CONNECTION =       0x00000080
FILE_COMPLETE_IF_OPLOCKED =         0x00000100
FILE_NO_EA_KNOWLEDGE =              0x00000200
FILE_OPEN_REMOTE_INSTANCE =         0x00000400
FILE_RANDOM_ACCESS =                0x00000800
FILE_DELETE_ON_CLOSE =              0x00001000
FILE_OPEN_BY_FILE_ID =              0x00002000
FILE_OPEN_FOR_BACKUP_INTENT =       0x00004000
FILE_NO_COMPRESSION =               0x00008000

if NTDDI_VERSION >= NTDDI_WIN7:
    FILE_OPEN_REQUIRING_OPLOCK =        0x00010000
    FILE_DISALLOW_EXCLUSIVE =           0x00020000

FILE_RESERVE_OPFILTER =             0x00100000
FILE_OPEN_REPARSE_POINT =           0x00200000
FILE_OPEN_NO_RECALL =               0x00400000
FILE_OPEN_FOR_FREE_SPACE_QUERY =    0x00800000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
FILE_SHARE_VALID_FLAGS = 0x00000007
FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_ARCHIVE = 0x00000020
FILE_ATTRIBUTE_DEVICE = 0x00000040
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_TEMPORARY = 0x00000100
FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_COMPRESSED = 0x00000800
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x00008000
FILE_ATTRIBUTE_VIRTUAL = 0x00010000
FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x00020000
FILE_ATTRIBUTE_EA = 0x00040000
FILE_ATTRIBUTE_PINNED = 0x00080000
FILE_ATTRIBUTE_UNPINNED = 0x00100000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
TREE_CONNECT_ATTRIBUTE_PRIVACY = 0x00004000
TREE_CONNECT_ATTRIBUTE_INTEGRITY = 0x00008000
TREE_CONNECT_ATTRIBUTE_GLOBAL = 0x00000004
TREE_CONNECT_ATTRIBUTE_PINNED = 0x00000002
FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL = 0x20000000
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_SECURITY = 0x00000100
FILE_ACTION_ADDED = 0x00000001
FILE_ACTION_REMOVED = 0x00000002
FILE_ACTION_MODIFIED = 0x00000003
FILE_ACTION_RENAMED_OLD_NAME = 0x00000004
FILE_ACTION_RENAMED_NEW_NAME = 0x00000005
MAILSLOT_NO_MESSAGE = DWORD(-1).value
MAILSLOT_WAIT_FOREVER = DWORD(-1).value
FILE_CASE_SENSITIVE_SEARCH = 0x00000001
FILE_CASE_PRESERVED_NAMES = 0x00000002
FILE_UNICODE_ON_DISK = 0x00000004
FILE_PERSISTENT_ACLS = 0x00000008
FILE_FILE_COMPRESSION = 0x00000010
FILE_VOLUME_QUOTAS = 0x00000020
FILE_SUPPORTS_SPARSE_FILES = 0x00000040
FILE_SUPPORTS_REPARSE_POINTS = 0x00000080
FILE_SUPPORTS_REMOTE_STORAGE = 0x00000100
FILE_RETURNS_CLEANUP_RESULT_INFO = 0x00000200
FILE_SUPPORTS_POSIX_UNLINK_RENAME = 0x00000400
FILE_SUPPORTS_BYPASS_IO = 0x00000800
FILE_SUPPORTS_STREAM_SNAPSHOTS = 0x00001000
FILE_SUPPORTS_CASE_SENSITIVE_DIRS = 0x00002000

FILE_VOLUME_IS_COMPRESSED = 0x00008000
FILE_SUPPORTS_OBJECT_IDS = 0x00010000
FILE_SUPPORTS_ENCRYPTION = 0x00020000
FILE_NAMED_STREAMS = 0x00040000
FILE_READ_ONLY_VOLUME = 0x00080000
FILE_SEQUENTIAL_WRITE_ONCE = 0x00100000
FILE_SUPPORTS_TRANSACTIONS = 0x00200000
FILE_SUPPORTS_HARD_LINKS = 0x00400000
FILE_SUPPORTS_EXTENDED_ATTRIBUTES = 0x00800000
FILE_SUPPORTS_OPEN_BY_FILE_ID = 0x01000000
FILE_SUPPORTS_USN_JOURNAL = 0x02000000
FILE_SUPPORTS_INTEGRITY_STREAMS = 0x04000000
FILE_SUPPORTS_BLOCK_REFCOUNTING = 0x08000000
FILE_SUPPORTS_SPARSE_VDL = 0x10000000
FILE_DAX_VOLUME = 0x20000000
FILE_SUPPORTS_GHOSTING = 0x40000000
FILE_INVALID_FILE_ID = LONGLONG(-1).value

class _FILE_ID_128(Structure):
    _fields_ = [('Identifier', BYTE * 16)]

FILE_ID_128 = _FILE_ID_128
PFILE_ID_128 = POINTER(FILE_ID_128)

class _FILE_NOTIFY_INFORMATION(Structure):
    _fields_ = [('NextEntryOffset', DWORD),
                ('Action', DWORD),
                ('FileNameLength', DWORD),
                ('FileName', WCHAR * 1)
    ]
    
FILE_NOTIFY_INFORMATION = _FILE_NOTIFY_INFORMATION
PFILE_NOTIFY_INFORMATION = POINTER(FILE_NOTIFY_INFORMATION)


if WIN32_WINNT >= WIN32_WINNT_WIN10:
    FILE_NAME_FLAG_HARDLINK = 0
    FILE_NAME_FLAG_NTFS = 0x01
    FILE_NAME_FLAG_DOS = 0x02
    FILE_NAME_FLAG_BOTH = 0x03
    FILE_NAME_FLAGS_UNSPECIFIED = 0x80

    class _FILE_NOTIFY_FULL_INFORMATION(Structure):
        class RepEaUnion(Union):
            _fields_ = [('ReparsePointTag', DWORD),
                        ('EaSize', DWORD)
            ]

        _anonymous_ = ['RepEaUnion']
        _fields_ = [('NextEntryOffset', DWORD),
                    ('Action', DWORD),
                    ('CreationTime', LARGE_INTEGER),
                    ('LastModificationTime', LARGE_INTEGER),
                    ('LastChangeTime', LARGE_INTEGER),
                    ('LastAccessTime', LARGE_INTEGER),
                    ('AllocatedLength', LARGE_INTEGER),
                    ('FileSize', LARGE_INTEGER),
                    ('FileAttributes', DWORD),
                    ('RepEaUnion', RepEaUnion),
                    ('FileId', LARGE_INTEGER),
                    ('ParentFileId', LARGE_INTEGER),
                    ('FileNameLength', WORD),
                    ('FileNameFlags', BYTE),
                    ('Reserved', BYTE),
                    ('FileName', WCHAR * 1)
        ]

    FILE_NOTIFY_FULL_INFORMATION = _FILE_NOTIFY_FULL_INFORMATION
    PFILE_NOTIFY_FULL_INFORMATION =  POINTER(FILE_NOTIFY_FULL_INFORMATION)

FILE_CS_FLAG_CASE_SENSITIVE_DIR = 0x00000001

class _FILE_SEGMENT_ELEMENT(Union):
    _fields_ = [('Buffer', PVOID64),
                ('Alignment', ULONGLONG)
    ]

FILE_SEGMENT_ELEMENT = _FILE_SEGMENT_ELEMENT
PFILE_SEGMENT_ELEMENT = POINTER(FILE_SEGMENT_ELEMENT)

if NTDDI_VERSION >= NTDDI_WIN8:
    FLUSH_FLAGS_FILE_DATA_ONLY = 0x00000001
    FLUSH_FLAGS_NO_SYNC = 0x00000002

if NTDDI_VERSION >= NTDDI_WIN10_RS1:
    FLUSH_FLAGS_FILE_DATA_SYNC_ONLY = 0x00000004

class _REPARSE_GUID_DATA_BUFFER(Structure):
    class GenericReparseBuffer(Structure):
        _fields_ = [('DataBuffer', BYTE * 1)]
    
    _anonymous_ = ['GenericReparseBuffer']
    _fields_ = [('ReparseTag', DWORD),
                ('ReparseDataLength', WORD),
                ('Reserved', WORD),
                ('ReparseGuid', GUID),
                ('GenericReparseBuffer', GenericReparseBuffer)
    ]

REPARSE_GUID_DATA_BUFFER = _REPARSE_GUID_DATA_BUFFER
PREPARSE_GUID_DATA_BUFFER = POINTER(REPARSE_GUID_DATA_BUFFER)

MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16 *1024

SYMLINK_FLAG_RELATIVE = 1

IO_REPARSE_TAG_RESERVED_ZERO = 0
IO_REPARSE_TAG_RESERVED_ONE = 1
IO_REPARSE_TAG_RESERVED_TWO = 2

IO_REPARSE_TAG_RESERVED_RANGE = IO_REPARSE_TAG_RESERVED_TWO

def IsReparseTagMicrosoft(_tag: int) -> int:
    return _tag & 0x80000000


def IsReparseTagNameSurrogate(_tag: int) -> int:
    return _tag & 0x20000000


def IsReparseTagDirectory(_tag: int) -> int:
    return _tag & 0x10000000


IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_HSM = 0xC0000004
IO_REPARSE_TAG_DRIVE_EXTENDER = 0x80000005
IO_REPARSE_TAG_HSM2 = 0x80000006
IO_REPARSE_TAG_SIS = 0x80000007
IO_REPARSE_TAG_WIM = 0x80000008
IO_REPARSE_TAG_CSV = 0x80000009
IO_REPARSE_TAG_DFS = 0x8000000A
IO_REPARSE_TAG_FILTER_MANAGER = 0x8000000B
IO_REPARSE_TAG_SYMLINK = 0xA000000C
IO_REPARSE_TAG_IIS_CACHE = 0xA0000010
IO_REPARSE_TAG_DFSR = 0x80000012
IO_REPARSE_TAG_DEDUP = 0x80000013
IO_REPARSE_TAG_NFS = 0x80000014
IO_REPARSE_TAG_FILE_PLACEHOLDER = 0x80000015
IO_REPARSE_TAG_WOF = 0x80000017
IO_REPARSE_TAG_WCI = 0x80000018
IO_REPARSE_TAG_WCI_1 = 0x90001018
IO_REPARSE_TAG_GLOBAL_REPARSE = 0xA0000019
IO_REPARSE_TAG_CLOUD = 0x9000001A
IO_REPARSE_TAG_CLOUD_1 = 0x9000101A
IO_REPARSE_TAG_CLOUD_2 = 0x9000201A
IO_REPARSE_TAG_CLOUD_3 = 0x9000301A
IO_REPARSE_TAG_CLOUD_4 = 0x9000401A
IO_REPARSE_TAG_CLOUD_5 = 0x9000501A
IO_REPARSE_TAG_CLOUD_6 = 0x9000601A
IO_REPARSE_TAG_CLOUD_7 = 0x9000701A
IO_REPARSE_TAG_CLOUD_8 = 0x9000801A
IO_REPARSE_TAG_CLOUD_9 = 0x9000901A
IO_REPARSE_TAG_CLOUD_A = 0x9000A01A
IO_REPARSE_TAG_CLOUD_B = 0x9000B01A
IO_REPARSE_TAG_CLOUD_C = 0x9000C01A
IO_REPARSE_TAG_CLOUD_D = 0x9000D01A
IO_REPARSE_TAG_CLOUD_E = 0x9000E01A
IO_REPARSE_TAG_CLOUD_F = 0x9000F01A
IO_REPARSE_TAG_CLOUD_MASK = 0x0000F000
IO_REPARSE_TAG_APPEXECLINK = 0x8000001B
IO_REPARSE_TAG_PROJFS = 0x9000001C
IO_REPARSE_TAG_STORAGE_SYNC = 0x8000001E
IO_REPARSE_TAG_WCI_TOMBSTONE = 0xA000001F
IO_REPARSE_TAG_UNHANDLED = 0x80000020
IO_REPARSE_TAG_ONEDRIVE = 0x80000021
IO_REPARSE_TAG_PROJFS_TOMBSTONE = 0xA0000022
IO_REPARSE_TAG_AF_UNIX = 0x80000023
IO_REPARSE_TAG_WCI_LINK = 0xA0000027
IO_REPARSE_TAG_WCI_LINK_1 = 0xA0001027
IO_REPARSE_TAG_DATALESS_CIM = 0xA0000028

IO_COMPLETION_MODIFY_STATE = 0x0002
IO_COMPLETION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                            SYNCHRONIZE | 
                            0x3
)

DUPLICATE_CLOSE_SOURCE = 0x00000001
DUPLICATE_SAME_ACCESS = 0x00000002

POWERBUTTON_ACTION_INDEX_NOTHING = 0
POWERBUTTON_ACTION_INDEX_SLEEP = 1
POWERBUTTON_ACTION_INDEX_HIBERNATE = 2
POWERBUTTON_ACTION_INDEX_SHUTDOWN = 3

POWERBUTTON_ACTION_VALUE_NOTHING = 0
POWERBUTTON_ACTION_VALUE_SLEEP = 2
POWERBUTTON_ACTION_VALUE_HIBERNATE = 3
POWERBUTTON_ACTION_VALUE_SHUTDOWN = 6

PERFSTATE_POLICY_CHANGE_IDEAL = 0
PERFSTATE_POLICY_CHANGE_SINGLE = 1
PERFSTATE_POLICY_CHANGE_ROCKET = 2
PERFSTATE_POLICY_CHANGE_MAX = PERFSTATE_POLICY_CHANGE_ROCKET

PROCESSOR_PERF_BOOST_POLICY_DISABLED = 0
PROCESSOR_PERF_BOOST_POLICY_MAX = 100

PROCESSOR_PERF_BOOST_MODE_DISABLED = 0
PROCESSOR_PERF_BOOST_MODE_ENABLED = 1
PROCESSOR_PERF_BOOST_MODE_AGGRESSIVE = 2
PROCESSOR_PERF_BOOST_MODE_EFFICIENT_ENABLED = 3
PROCESSOR_PERF_BOOST_MODE_EFFICIENT_AGGRESSIVE = 4
PROCESSOR_PERF_BOOST_MODE_MAX = PROCESSOR_PERF_BOOST_MODE_EFFICIENT_AGGRESSIVE

CORE_PARKING_POLICY_CHANGE_IDEAL = 0
CORE_PARKING_POLICY_CHANGE_SINGLE = 1
CORE_PARKING_POLICY_CHANGE_ROCKET = 2
CORE_PARKING_POLICY_CHANGE_MULTISTEP = 3
CORE_PARKING_POLICY_CHANGE_MAX = CORE_PARKING_POLICY_CHANGE_MULTISTEP

POWER_DEVICE_IDLE_POLICY_PERFORMANCE = 0
POWER_DEVICE_IDLE_POLICY_CONSERVATIVE = 1

GUID_MAX_POWER_SAVINGS = DEFINE_GUID(0xa1841308, 0x3541, 0x4fab, 0xbc, 0x81, 0xf7, 0x15, 0x56, 0xf2, 0x0b, 0x4a)
GUID_MIN_POWER_SAVINGS = DEFINE_GUID(0x8c5e7fda, 0xe8bf, 0x4a96, 0x9a, 0x85, 0xa6, 0xe2, 0x3a, 0x8c, 0x63, 0x5c)
GUID_TYPICAL_POWER_SAVINGS = DEFINE_GUID(0x381b4222, 0xf694, 0x41f0, 0x96, 0x85, 0xff, 0x5b, 0xb2, 0x60, 0xdf, 0x2e)
NO_SUBGROUP_GUID = DEFINE_GUID(0xfea3413e, 0x7e05, 0x4911, 0x9a, 0x71, 0x70, 0x03, 0x31, 0xf1, 0xc2, 0x94)
ALL_POWERSCHEMES_GUID = DEFINE_GUID(0x68a1e95e, 0x13ea, 0x41e1, 0x80, 0x11, 0x0c, 0x49, 0x6c, 0xa4, 0x90, 0xb0)
GUID_POWERSCHEME_PERSONALITY = DEFINE_GUID(0x245d8541, 0x3943, 0x4422, 0xb0, 0x25, 0x13, 0xa7, 0x84, 0xf6, 0x79, 0xb7)
GUID_ACTIVE_POWERSCHEME = DEFINE_GUID(0x31f9f286, 0x5084, 0x42fe, 0xb7, 0x20, 0x2b, 0x02, 0x64, 0x99, 0x37, 0x63)
GUID_IDLE_RESILIENCY_SUBGROUP = DEFINE_GUID(0x2e601130, 0x5351, 0x4d9d, 0x8e, 0x4, 0x25, 0x29, 0x66, 0xba, 0xd0, 0x54)
GUID_IDLE_RESILIENCY_PERIOD = DEFINE_GUID(0xc42b79aa, 0xaa3a, 0x484b, 0xa9, 0x8f, 0x2c, 0xf3, 0x2a, 0xa9, 0xa, 0x28)
GUID_DISK_COALESCING_POWERDOWN_TIMEOUT = DEFINE_GUID(0xc36f0eb4, 0x2988, 0x4a70, 0x8e, 0xee, 0x8, 0x84, 0xfc, 0x2c, 0x24, 0x33)
GUID_EXECUTION_REQUIRED_REQUEST_TIMEOUT = DEFINE_GUID(0x3166bc41, 0x7e98, 0x4e03, 0xb3, 0x4e, 0xec, 0xf, 0x5f, 0x2b, 0x21, 0x8e)
GUID_VIDEO_SUBGROUP = DEFINE_GUID(0x7516b95f, 0xf776, 0x4464, 0x8c, 0x53, 0x06, 0x16, 0x7f, 0x40, 0xcc, 0x99)
GUID_VIDEO_POWERDOWN_TIMEOUT = DEFINE_GUID(0x3c0bc021, 0xc8a8, 0x4e07, 0xa9, 0x73, 0x6b, 0x14, 0xcb, 0xcb, 0x2b, 0x7e)
GUID_VIDEO_ANNOYANCE_TIMEOUT = DEFINE_GUID(0x82dbcf2d, 0xcd67, 0x40c5, 0xbf, 0xdc, 0x9f, 0x1a, 0x5c, 0xcd, 0x46, 0x63)
GUID_VIDEO_ADAPTIVE_PERCENT_INCREASE = DEFINE_GUID(0xeed904df, 0xb142, 0x4183, 0xb1, 0x0b, 0x5a, 0x11, 0x97, 0xa3, 0x78, 0x64)
GUID_VIDEO_DIM_TIMEOUT = DEFINE_GUID(0x17aaa29b, 0x8b43, 0x4b94, 0xaa, 0xfe, 0x35, 0xf6, 0x4d, 0xaa, 0xf1, 0xee)
GUID_VIDEO_ADAPTIVE_POWERDOWN = DEFINE_GUID(0x90959d22, 0xd6a1, 0x49b9, 0xaf, 0x93, 0xbc, 0xe8, 0x85, 0xad, 0x33, 0x5b)
GUID_MONITOR_POWER_ON = DEFINE_GUID(0x02731015, 0x4510, 0x4526, 0x99, 0xe6, 0xe5, 0xa1, 0x7e, 0xbd, 0x1a, 0xea)
GUID_DEVICE_POWER_POLICY_VIDEO_BRIGHTNESS = DEFINE_GUID(0xaded5e82, 0xb909, 0x4619, 0x99, 0x49, 0xf5, 0xd7, 0x1d, 0xac, 0x0b, 0xcb)
GUID_DEVICE_POWER_POLICY_VIDEO_DIM_BRIGHTNESS = DEFINE_GUID(0xf1fbfde2, 0xa960, 0x4165, 0x9f, 0x88, 0x50, 0x66, 0x79, 0x11, 0xce, 0x96)
GUID_VIDEO_CURRENT_MONITOR_BRIGHTNESS = DEFINE_GUID(0x8ffee2c6, 0x2d01, 0x46be, 0xad, 0xb9, 0x39, 0x8a, 0xdd, 0xc5, 0xb4, 0xff)
GUID_VIDEO_ADAPTIVE_DISPLAY_BRIGHTNESS = DEFINE_GUID(0xfbd9aa66, 0x9553, 0x4097, 0xba, 0x44, 0xed, 0x6e, 0x9d, 0x65, 0xea, 0xb8)
GUID_CONSOLE_DISPLAY_STATE = DEFINE_GUID(0x6fe69556, 0x704a, 0x47a0, 0x8f, 0x24, 0xc2, 0x8d, 0x93, 0x6f, 0xda, 0x47)
GUID_ALLOW_DISPLAY_REQUIRED = DEFINE_GUID(0xa9ceb8da, 0xcd46, 0x44fb, 0xa9, 0x8b, 0x02, 0xaf, 0x69, 0xde, 0x46, 0x23)
GUID_VIDEO_CONSOLE_LOCK_TIMEOUT = DEFINE_GUID(0x8ec4b3a5, 0x6868, 0x48c2, 0xbe, 0x75, 0x4f, 0x30, 0x44, 0xbe, 0x88, 0xa7)
GUID_ADAPTIVE_POWER_BEHAVIOR_SUBGROUP = DEFINE_GUID(0x8619b916, 0xe004, 0x4dd8, 0x9b, 0x66, 0xda, 0xe8, 0x6f, 0x80, 0x66, 0x98)
GUID_NON_ADAPTIVE_INPUT_TIMEOUT = DEFINE_GUID(0x5adbbfbc, 0x74e, 0x4da1, 0xba, 0x38, 0xdb, 0x8b, 0x36, 0xb2, 0xc8, 0xf3)
GUID_DISK_SUBGROUP = DEFINE_GUID(0x0012ee47, 0x9041, 0x4b5d, 0x9b, 0x77, 0x53, 0x5f, 0xba, 0x8b, 0x14, 0x42)
GUID_DISK_POWERDOWN_TIMEOUT = DEFINE_GUID(0x6738e2c4, 0xe8a5, 0x4a42, 0xb1, 0x6a, 0xe0, 0x40, 0xe7, 0x69, 0x75, 0x6e)
GUID_DISK_IDLE_TIMEOUT = DEFINE_GUID(0x58e39ba8, 0xb8e6, 0x4ef6, 0x90, 0xd0, 0x89, 0xae, 0x32, 0xb2, 0x58, 0xd6)
GUID_DISK_BURST_IGNORE_THRESHOLD = DEFINE_GUID(0x80e3c60e, 0xbb94, 0x4ad8, 0xbb, 0xe0, 0x0d, 0x31, 0x95, 0xef, 0xc6, 0x63)
GUID_DISK_ADAPTIVE_POWERDOWN = DEFINE_GUID(0x396a32e1, 0x499a, 0x40b2, 0x91, 0x24, 0xa9, 0x6a, 0xfe, 0x70, 0x76, 0x67)
GUID_SLEEP_SUBGROUP = DEFINE_GUID(0x238c9fa8, 0x0aad, 0x41ed, 0x83, 0xf4, 0x97, 0xbe, 0x24, 0x2c, 0x8f, 0x20)
GUID_SLEEP_IDLE_THRESHOLD = DEFINE_GUID(0x81cd32e0, 0x7833, 0x44f3, 0x87, 0x37, 0x70, 0x81, 0xf3, 0x8d, 0x1f, 0x70)
GUID_STANDBY_TIMEOUT = DEFINE_GUID(0x29f6c1db, 0x86da, 0x48c5, 0x9f, 0xdb, 0xf2, 0xb6, 0x7b, 0x1f, 0x44, 0xda)
GUID_UNATTEND_SLEEP_TIMEOUT = DEFINE_GUID(0x7bc4a2f9, 0xd8fc, 0x4469, 0xb0, 0x7b, 0x33, 0xeb, 0x78, 0x5a, 0xac, 0xa0)
GUID_HIBERNATE_TIMEOUT = DEFINE_GUID(0x9d7815a6, 0x7ee4, 0x497e, 0x88, 0x88, 0x51, 0x5a, 0x05, 0xf0, 0x23, 0x64)
GUID_HIBERNATE_FASTS4_POLICY = DEFINE_GUID(0x94ac6d29, 0x73ce, 0x41a6, 0x80, 0x9f, 0x63, 0x63, 0xba, 0x21, 0xb4, 0x7e)
GUID_CRITICAL_POWER_TRANSITION = DEFINE_GUID(0xb7a27025, 0xe569, 0x46c2, 0xa5, 0x04, 0x2b, 0x96, 0xca, 0xd2, 0x25, 0xa1)
GUID_SYSTEM_AWAYMODE = DEFINE_GUID(0x98a7f580, 0x01f7, 0x48aa, 0x9c, 0x0f, 0x44, 0x35, 0x2c, 0x29, 0xe5, 0xc0)
GUID_ALLOW_AWAYMODE = DEFINE_GUID(0x25dfa149, 0x5dd1, 0x4736, 0xb5, 0xab, 0xe8, 0xa3, 0x7b, 0x5b, 0x81, 0x87)
GUID_ALLOW_STANDBY_STATES = DEFINE_GUID(0xabfc2519, 0x3608, 0x4c2a, 0x94, 0xea, 0x17, 0x1b, 0x0e, 0xd5, 0x46, 0xab)
GUID_ALLOW_RTC_WAKE = DEFINE_GUID(0xbd3b718a, 0x0680, 0x4d9d, 0x8a, 0xb2, 0xe1, 0xd2, 0xb4, 0xac, 0x80, 0x6d)
GUID_ALLOW_SYSTEM_REQUIRED = DEFINE_GUID(0xa4b195f5, 0x8225, 0x47d8, 0x80, 0x12, 0x9d, 0x41, 0x36, 0x97, 0x86, 0xe2)
GUID_SYSTEM_BUTTON_SUBGROUP = DEFINE_GUID(0x4f971e89, 0xeebd, 0x4455, 0xa8, 0xde, 0x9e, 0x59, 0x04, 0x0e, 0x73, 0x47)
GUID_POWERBUTTON_ACTION = DEFINE_GUID(0x7648efa3, 0xdd9c, 0x4e3e, 0xb5, 0x66, 0x50, 0xf9, 0x29, 0x38, 0x62, 0x80)
GUID_SLEEPBUTTON_ACTION = DEFINE_GUID(0x96996bc0, 0xad50, 0x47ec, 0x92, 0x3b, 0x6f, 0x41, 0x87, 0x4d, 0xd9, 0xeb)
GUID_USERINTERFACEBUTTON_ACTION = DEFINE_GUID(0xa7066653, 0x8d6c, 0x40a8, 0x91, 0x0e, 0xa1, 0xf5, 0x4b, 0x84, 0xc7, 0xe5)
GUID_LIDCLOSE_ACTION = DEFINE_GUID(0x5ca83367, 0x6e45, 0x459f, 0xa2, 0x7b, 0x47, 0x6b, 0x1d, 0x01, 0xc9, 0x36)
GUID_LIDOPEN_POWERSTATE = DEFINE_GUID(0x99ff10e7, 0x23b1, 0x4c07, 0xa9, 0xd1, 0x5c, 0x32, 0x06, 0xd7, 0x41, 0xb4)
GUID_BATTERY_SUBGROUP = DEFINE_GUID(0xe73a048d, 0xbf27, 0x4f12, 0x97, 0x31, 0x8b, 0x20, 0x76, 0xe8, 0x89, 0x1f)
GUID_BATTERY_DISCHARGE_ACTION_0 = DEFINE_GUID(0x637ea02f, 0xbbcb, 0x4015, 0x8e, 0x2c, 0xa1, 0xc7, 0xb9, 0xc0, 0xb5, 0x46)
GUID_BATTERY_DISCHARGE_LEVEL_0 = DEFINE_GUID(0x9a66d8d7, 0x4ff7, 0x4ef9, 0xb5, 0xa2, 0x5a, 0x32, 0x6c, 0xa2, 0xa4, 0x69)
GUID_BATTERY_DISCHARGE_FLAGS_0 = DEFINE_GUID(0x5dbb7c9f, 0x38e9, 0x40d2, 0x97, 0x49, 0x4f, 0x8a, 0x0e, 0x9f, 0x64, 0x0f)
GUID_BATTERY_DISCHARGE_ACTION_1 = DEFINE_GUID(0xd8742dcb, 0x3e6a, 0x4b3c, 0xb3, 0xfe, 0x37, 0x46, 0x23, 0xcd, 0xcf, 0x06)
GUID_BATTERY_DISCHARGE_LEVEL_1 = DEFINE_GUID(0x8183ba9a, 0xe910, 0x48da, 0x87, 0x69, 0x14, 0xae, 0x6d, 0xc1, 0x17, 0x0a)
GUID_BATTERY_DISCHARGE_FLAGS_1 = DEFINE_GUID(0xbcded951, 0x187b, 0x4d05, 0xbc, 0xcc, 0xf7, 0xe5, 0x19, 0x60, 0xc2, 0x58)
GUID_BATTERY_DISCHARGE_ACTION_2 = DEFINE_GUID(0x421cba38, 0x1a8e, 0x4881, 0xac, 0x89, 0xe3, 0x3a, 0x8b, 0x04, 0xec, 0xe4)
GUID_BATTERY_DISCHARGE_LEVEL_2 = DEFINE_GUID(0x07a07ca2, 0xadaf, 0x40d7, 0xb0, 0x77, 0x53, 0x3a, 0xad, 0xed, 0x1b, 0xfa)
GUID_BATTERY_DISCHARGE_FLAGS_2 = DEFINE_GUID(0x7fd2f0c4, 0xfeb7, 0x4da3, 0x81, 0x17, 0xe3, 0xfb, 0xed, 0xc4, 0x65, 0x82)
GUID_BATTERY_DISCHARGE_ACTION_3 = DEFINE_GUID(0x80472613, 0x9780, 0x455e, 0xb3, 0x08, 0x72, 0xd3, 0x00, 0x3c, 0xf2, 0xf8)
GUID_BATTERY_DISCHARGE_LEVEL_3 = DEFINE_GUID(0x58afd5a6, 0xc2dd, 0x47d2, 0x9f, 0xbf, 0xef, 0x70, 0xcc, 0x5c, 0x59, 0x65)
GUID_BATTERY_DISCHARGE_FLAGS_3 = DEFINE_GUID(0x73613ccf, 0xdbfa, 0x4279, 0x83, 0x56, 0x49, 0x35, 0xf6, 0xbf, 0x62, 0xf3)
GUID_PROCESSOR_SETTINGS_SUBGROUP = DEFINE_GUID(0x54533251, 0x82be, 0x4824, 0x96, 0xc1, 0x47, 0xb6, 0x0b, 0x74, 0x0d, 0x00)
GUID_PROCESSOR_THROTTLE_POLICY = DEFINE_GUID(0x57027304, 0x4af6, 0x4104, 0x92, 0x60, 0xe3, 0xd9, 0x52, 0x48, 0xfc, 0x36)
GUID_PROCESSOR_THROTTLE_MAXIMUM = DEFINE_GUID(0xbc5038f7, 0x23e0, 0x4960, 0x96, 0xda, 0x33, 0xab, 0xaf, 0x59, 0x35, 0xec)
GUID_PROCESSOR_THROTTLE_MINIMUM = DEFINE_GUID(0x893dee8e, 0x2bef, 0x41e0, 0x89, 0xc6, 0xb5, 0x5d, 0x09, 0x29, 0x96, 0x4c)
GUID_PROCESSOR_ALLOW_THROTTLING = DEFINE_GUID(0x3b04d4fd, 0x1cc7, 0x4f23, 0xab, 0x1c, 0xd1, 0x33, 0x78, 0x19, 0xc4, 0xbb)
GUID_PROCESSOR_IDLESTATE_POLICY = DEFINE_GUID(0x68f262a7, 0xf621, 0x4069, 0xb9, 0xa5, 0x48, 0x74, 0x16, 0x9b, 0xe2, 0x3c)
GUID_PROCESSOR_PERFSTATE_POLICY = DEFINE_GUID(0xbbdc3814, 0x18e9, 0x4463, 0x8a, 0x55, 0xd1, 0x97, 0x32, 0x7c, 0x45, 0xc0)
GUID_PROCESSOR_PERF_INCREASE_THRESHOLD = DEFINE_GUID(0x06cadf0e, 0x64ed, 0x448a, 0x89, 0x27, 0xce, 0x7b, 0xf9, 0x0e, 0xb3, 0x5d)
GUID_PROCESSOR_PERF_DECREASE_THRESHOLD = DEFINE_GUID(0x12a0ab44, 0xfe28, 0x4fa9, 0xb3, 0xbd, 0x4b, 0x64, 0xf4, 0x49, 0x60, 0xa6)
GUID_PROCESSOR_PERF_INCREASE_POLICY = DEFINE_GUID(0x465e1f50, 0xb610, 0x473a, 0xab, 0x58, 0x0, 0xd1, 0x7, 0x7d, 0xc4, 0x18)
GUID_PROCESSOR_PERF_DECREASE_POLICY = DEFINE_GUID(0x40fbefc7, 0x2e9d, 0x4d25, 0xa1, 0x85, 0xc, 0xfd, 0x85, 0x74, 0xba, 0xc6)
GUID_PROCESSOR_PERF_INCREASE_TIME = DEFINE_GUID(0x984cf492, 0x3bed, 0x4488, 0xa8, 0xf9, 0x42, 0x86, 0xc9, 0x7b, 0xf5, 0xaa)
GUID_PROCESSOR_PERF_DECREASE_TIME = DEFINE_GUID(0xd8edeb9b, 0x95cf, 0x4f95, 0xa7, 0x3c, 0xb0, 0x61, 0x97, 0x36, 0x93, 0xc8)
GUID_PROCESSOR_PERF_TIME_CHECK = DEFINE_GUID(0x4d2b0152, 0x7d5c, 0x498b, 0x88, 0xe2, 0x34, 0x34, 0x53, 0x92, 0xa2, 0xc5)
GUID_PROCESSOR_PERF_BOOST_POLICY = DEFINE_GUID(0x45bcc044, 0xd885, 0x43e2, 0x86, 0x5, 0xee, 0xe, 0xc6, 0xe9, 0x6b, 0x59)
GUID_PROCESSOR_PERF_BOOST_MODE = DEFINE_GUID(0xbe337238, 0xd82, 0x4146, 0xa9, 0x60, 0x4f, 0x37, 0x49, 0xd4, 0x70, 0xc7)
GUID_PROCESSOR_IDLE_ALLOW_SCALING = DEFINE_GUID(0x6c2993b0, 0x8f48, 0x481f, 0xbc, 0xc6, 0x0, 0xdd, 0x27, 0x42, 0xaa, 0x6)
GUID_PROCESSOR_IDLE_DISABLE = DEFINE_GUID(0x5d76a2ca, 0xe8c0, 0x402f, 0xa1, 0x33, 0x21, 0x58, 0x49, 0x2d, 0x58, 0xad)
GUID_PROCESSOR_IDLE_STATE_MAXIMUM = DEFINE_GUID(0x9943e905, 0x9a30, 0x4ec1, 0x9b, 0x99, 0x44, 0xdd, 0x3b, 0x76, 0xf7, 0xa2)
GUID_PROCESSOR_IDLE_TIME_CHECK = DEFINE_GUID(0xc4581c31, 0x89ab, 0x4597, 0x8e, 0x2b, 0x9c, 0x9c, 0xab, 0x44, 0xe, 0x6b)
GUID_PROCESSOR_IDLE_DEMOTE_THRESHOLD = DEFINE_GUID(0x4b92d758, 0x5a24, 0x4851, 0xa4, 0x70, 0x81, 0x5d, 0x78, 0xae, 0xe1, 0x19)
GUID_PROCESSOR_IDLE_PROMOTE_THRESHOLD = DEFINE_GUID(0x7b224883, 0xb3cc, 0x4d79, 0x81, 0x9f, 0x83, 0x74, 0x15, 0x2c, 0xbe, 0x7c)
GUID_PROCESSOR_CORE_PARKING_INCREASE_THRESHOLD = DEFINE_GUID(0xdf142941, 0x20f3, 0x4edf, 0x9a, 0x4a, 0x9c, 0x83, 0xd3, 0xd7, 0x17, 0xd1)
GUID_PROCESSOR_CORE_PARKING_DECREASE_THRESHOLD = DEFINE_GUID(0x68dd2f27, 0xa4ce, 0x4e11, 0x84, 0x87, 0x37, 0x94, 0xe4, 0x13, 0x5d, 0xfa)
GUID_PROCESSOR_CORE_PARKING_INCREASE_POLICY = DEFINE_GUID(0xc7be0679, 0x2817, 0x4d69, 0x9d, 0x02, 0x51, 0x9a, 0x53, 0x7e, 0xd0, 0xc6)
GUID_PROCESSOR_CORE_PARKING_DECREASE_POLICY = DEFINE_GUID(0x71021b41, 0xc749, 0x4d21, 0xbe, 0x74, 0xa0, 0x0f, 0x33, 0x5d, 0x58, 0x2b)
GUID_PROCESSOR_CORE_PARKING_MAX_CORES = DEFINE_GUID(0xea062031, 0x0e34, 0x4ff1, 0x9b, 0x6d, 0xeb, 0x10, 0x59, 0x33, 0x40, 0x28)
GUID_PROCESSOR_CORE_PARKING_MIN_CORES = DEFINE_GUID(0x0cc5b647, 0xc1df, 0x4637, 0x89, 0x1a, 0xde, 0xc3, 0x5c, 0x31, 0x85, 0x83)
GUID_PROCESSOR_CORE_PARKING_INCREASE_TIME = DEFINE_GUID(0x2ddd5a84, 0x5a71, 0x437e, 0x91, 0x2a, 0xdb, 0x0b, 0x8c, 0x78, 0x87, 0x32)
GUID_PROCESSOR_CORE_PARKING_DECREASE_TIME = DEFINE_GUID(0xdfd10d17, 0xd5eb, 0x45dd, 0x87, 0x7a, 0x9a, 0x34, 0xdd, 0xd1, 0x5c, 0x82)
GUID_PROCESSOR_CORE_PARKING_AFFINITY_HISTORY_DECREASE_FACTOR = DEFINE_GUID(0x8f7b45e3, 0xc393, 0x480a, 0x87, 0x8c, 0xf6, 0x7a, 0xc3, 0xd0, 0x70, 0x82)
GUID_PROCESSOR_CORE_PARKING_AFFINITY_HISTORY_THRESHOLD = DEFINE_GUID(0x5b33697b, 0xe89d, 0x4d38, 0xaa, 0x46, 0x9e, 0x7d, 0xfb, 0x7c, 0xd2, 0xf9)
GUID_PROCESSOR_CORE_PARKING_AFFINITY_WEIGHTING = DEFINE_GUID(0xe70867f1, 0xfa2f, 0x4f4e, 0xae, 0xa1, 0x4d, 0x8a, 0x0b, 0xa2, 0x3b, 0x20)
GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_HISTORY_DECREASE_FACTOR = DEFINE_GUID(0x1299023c, 0xbc28, 0x4f0a, 0x81, 0xec, 0xd3, 0x29, 0x5a, 0x8d, 0x81, 0x5d)
GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_HISTORY_THRESHOLD = DEFINE_GUID(0x9ac18e92, 0xaa3c, 0x4e27, 0xb3, 0x07, 0x01, 0xae, 0x37, 0x30, 0x71, 0x29)
GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_WEIGHTING = DEFINE_GUID(0x8809c2d8, 0xb155, 0x42d4, 0xbc, 0xda, 0x0d, 0x34, 0x56, 0x51, 0xb1, 0xdb)
GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_THRESHOLD = DEFINE_GUID(0x943c8cb6, 0x6f93, 0x4227, 0xad, 0x87, 0xe9, 0xa3, 0xfe, 0xec, 0x08, 0xd1)
GUID_PROCESSOR_PARKING_CORE_OVERRIDE = DEFINE_GUID(0xa55612aa, 0xf624, 0x42c6, 0xa4, 0x43, 0x73, 0x97, 0xd0, 0x64, 0xc0, 0x4f)
GUID_PROCESSOR_PARKING_PERF_STATE = DEFINE_GUID(0x447235c7, 0x6a8d, 0x4cc0, 0x8e, 0x24, 0x9e, 0xaf, 0x70, 0xb9, 0x6e, 0x2b)
GUID_PROCESSOR_PARKING_CONCURRENCY_THRESHOLD = DEFINE_GUID(0x2430ab6f, 0xa520, 0x44a2, 0x96, 0x01, 0xf7, 0xf2, 0x3b, 0x51, 0x34, 0xb1)
GUID_PROCESSOR_PARKING_HEADROOM_THRESHOLD = DEFINE_GUID(0xf735a673, 0x2066, 0x4f80, 0xa0, 0xc5, 0xdd, 0xee, 0x0c, 0xf1, 0xbf, 0x5d)
GUID_PROCESSOR_PERF_HISTORY = DEFINE_GUID(0x7d24baa7, 0x0b84, 0x480f, 0x84, 0x0c, 0x1b, 0x07, 0x43, 0xc0, 0x0f, 0x5f)
GUID_PROCESSOR_PERF_LATENCY_HINT = DEFINE_GUID(0x0822df31, 0x9c83, 0x441c, 0xa0, 0x79, 0x0d, 0xe4, 0xcf, 0x00, 0x9c, 0x7b)
GUID_PROCESSOR_DISTRIBUTE_UTILITY = DEFINE_GUID(0xe0007330, 0xf589, 0x42ed, 0xa4, 0x01, 0x5d, 0xdb, 0x10, 0xe7, 0x85, 0xd3)
GUID_SYSTEM_COOLING_POLICY = DEFINE_GUID(0x94d3a615, 0xa899, 0x4ac5, 0xae, 0x2b, 0xe4, 0xd8, 0xf6, 0x34, 0x36, 0x7f)
GUID_LOCK_CONSOLE_ON_WAKE = DEFINE_GUID(0x0e796bdb, 0x100d, 0x47d6, 0xa2, 0xd5, 0xf7, 0xd2, 0xda, 0xa5, 0x1f, 0x51)
GUID_DEVICE_IDLE_POLICY = DEFINE_GUID(0x4faab71a, 0x92e5, 0x4726, 0xb5, 0x31, 0x22, 0x45, 0x59, 0x67, 0x2d, 0x19)
GUID_ACDC_POWER_SOURCE = DEFINE_GUID(0x5d3e9a59, 0xe9d5, 0x4b00, 0xa6, 0xbd, 0xff, 0x34, 0xff, 0x51, 0x65, 0x48)
GUID_LIDSWITCH_STATE_CHANGE = DEFINE_GUID(0xba3e0f4d, 0xb817, 0x4094, 0xa2, 0xd1, 0xd5, 0x63, 0x79, 0xe6, 0xa0, 0xf3)
GUID_BATTERY_PERCENTAGE_REMAINING = DEFINE_GUID(0xa7ad8041, 0xb45a, 0x4cae, 0x87, 0xa3, 0xee, 0xcb, 0xb4, 0x68, 0xa9, 0xe1)
GUID_GLOBAL_USER_PRESENCE = DEFINE_GUID(0x786e8a1d, 0xb427, 0x4344, 0x92, 0x7, 0x9, 0xe7, 0xb, 0xdc, 0xbe, 0xa9)
GUID_SESSION_DISPLAY_STATUS = DEFINE_GUID(0x2b84c20e, 0xad23, 0x4ddf, 0x93, 0xdb, 0x5, 0xff, 0xbd, 0x7e, 0xfc, 0xa5)
GUID_SESSION_USER_PRESENCE = DEFINE_GUID(0x3c0f4548, 0xc03f, 0x4c4d, 0xb9, 0xf2, 0x23, 0x7e, 0xde, 0x68, 0x63, 0x76)
GUID_IDLE_BACKGROUND_TASK = DEFINE_GUID(0x515c31d8, 0xf734, 0x163d, 0xa0, 0xfd, 0x11, 0xa0, 0x8c, 0x91, 0xe8, 0xf1)
GUID_BACKGROUND_TASK_NOTIFICATION = DEFINE_GUID(0xcf23f240, 0x2a54, 0x48d8, 0xb1, 0x14, 0xde, 0x15, 0x18, 0xff, 0x05, 0x2e)
GUID_APPLAUNCH_BUTTON = DEFINE_GUID(0x1a689231, 0x7399, 0x4e9a, 0x8f, 0x99, 0xb7, 0x1f, 0x99, 0x9d, 0xb3, 0xfa)
GUID_PCIEXPRESS_SETTINGS_SUBGROUP = DEFINE_GUID(0x501a4d13, 0x42af, 0x4429, 0x9f, 0xd1, 0xa8, 0x21, 0x8c, 0x26, 0x8e, 0x20)
GUID_PCIEXPRESS_ASPM_POLICY = DEFINE_GUID(0xee12f906, 0xd277, 0x404b, 0xb6, 0xda, 0xe5, 0xfa, 0x1a, 0x57, 0x6d, 0xf5)
GUID_ENABLE_SWITCH_FORCED_SHUTDOWN = DEFINE_GUID(0x833a6b62, 0xdfa4, 0x46d1, 0x82, 0xf8, 0xe0, 0x9e, 0x34, 0xd0, 0x29, 0xd6)

PowerSystemUnspecified = 0
PowerSystemWorking = 1
PowerSystemSleeping1 = 2
PowerSystemSleeping2 = 3
PowerSystemSleeping3 = 4
PowerSystemHibernate = 5
PowerSystemShutdown = 6
PowerSystemMaximum = 7

class _SYSTEM_POWER_STATE(enum.IntFlag):
    PowerSystemUnspecified = 0
    PowerSystemWorking = 1
    PowerSystemSleeping1 = 2
    PowerSystemSleeping2 = 3
    PowerSystemSleeping3 = 4
    PowerSystemHibernate = 5
    PowerSystemShutdown = 6
    PowerSystemMaximum = 7

SYSTEM_POWER_STATE = _SYSTEM_POWER_STATE
PSYSTEM_POWER_STATE = SYSTEM_POWER_STATE

POWER_SYSTEM_MAXIMUM = 7

PowerActionNone = 0
PowerActionReserved = 1
PowerActionSleep = 2
PowerActionHibernat = 3
PowerActionShutdown = 4
PowerActionShutdownReset = 5
PowerActionShutdownOff = 6
PowerActionWarmEject = 7

class POWER_ACTION(enum.IntFlag):
    PowerActionNone = 0
    PowerActionReserved = 1
    PowerActionSleep = 2
    PowerActionHibernat = 3
    PowerActionShutdown = 4
    PowerActionShutdownReset = 5
    PowerActionShutdownOff = 6
    PowerActionWarmEject = 7

PPOWER_ACTION = POWER_ACTION

PowerDeviceUnspecified = 0
PowerDeviceD0 = 1
PowerDeviceD1 = 2
PowerDeviceD2 = 3
PowerDeviceD3 = 4
PowerDeviceMaximum = 5

class _DEVICE_POWER_STATE(enum.IntFlag):
    PowerDeviceUnspecified = 0
    PowerDeviceD0 = 1
    PowerDeviceD1 = 2
    PowerDeviceD2 = 3
    PowerDeviceD3 = 4
    PowerDeviceMaximum = 5

DEVICE_POWER_STATE = _DEVICE_POWER_STATE
PDEVICE_POWER_STATE = DEVICE_POWER_STATE

PowerMonitorOff = 0
PowerMonitorOn = 1
PowerMonitorDim = 2

class _MONITOR_DISPLAY_STATE(enum.IntFlag):
    PowerMonitorOff = 0
    PowerMonitorOn = 1
    PowerMonitorDim = 2

MONITOR_DISPLAY_STATE = _MONITOR_DISPLAY_STATE
PMONITOR_DISPLAY_STATE = MONITOR_DISPLAY_STATE

PowerUserPresent = 0,
PowerUserNotPresent = 1
PowerUserInactive = 2
PowerUserMaximum = 3
PowerUserInvalid = PowerUserMaximum

class _USER_ACTIVITY_PRESENCE(enum.IntFlag):
    PowerUserPresent = 0,
    PowerUserNotPresent = 1
    PowerUserInactive = 2
    PowerUserMaximum = 3
    PowerUserInvalid = PowerUserMaximum

USER_ACTIVITY_PRESENCE = _USER_ACTIVITY_PRESENCE
PUSER_ACTIVITY_PRESENCE = USER_ACTIVITY_PRESENCE

ES_SYSTEM_REQUIRED = DWORD(0x00000001).value
ES_DISPLAY_REQUIRED = DWORD(0x00000002).value
ES_USER_PRESENT = DWORD(0x00000004).value
ES_AWAYMODE_REQUIRED = DWORD(0x00000040).value
ES_CONTINUOUS = DWORD(0x80000000).value

EXECUTION_STATE = DWORD
PEXECUTION_STATE = PDWORD

LT_DONT_CARE = 0
LT_LOWEST_LATENCY = 1

class LATENCY_TIME(enum.IntFlag):
    LT_DONT_CARE = 0
    LT_LOWEST_LATENCY = 1

DIAGNOSTIC_REASON_VERSION = 0
POWER_REQUEST_CONTEXT_VERSION = 0

DIAGNOSTIC_REASON_SIMPLE_STRING = 0x00000001
DIAGNOSTIC_REASON_DETAILED_STRING = 0x00000002
DIAGNOSTIC_REASON_NOT_SPECIFIED = 0x80000000
DIAGNOSTIC_REASON_INVALID_FLAGS = (~0x80000003)

POWER_REQUEST_CONTEXT_SIMPLE_STRING = 0x00000001
POWER_REQUEST_CONTEXT_DETAILED_STRING = 0x00000002

PowerRequestDisplayRequired = 0
PowerRequestSystemRequired = 1
PowerRequestAwayModeRequired = 2
PowerRequestExecutionRequired = 3

class _POWER_REQUEST_TYPE(enum.IntFlag):
    PowerRequestDisplayRequired = 0
    PowerRequestSystemRequired = 1
    PowerRequestAwayModeRequired = 2
    PowerRequestExecutionRequired = 3

POWER_REQUEST_TYPE = _POWER_REQUEST_TYPE
PPOWER_REQUEST_TYPE = POWER_REQUEST_TYPE

PDCAP_D0_SUPPORTED = 0x00000001
PDCAP_D1_SUPPORTED = 0x00000002
PDCAP_D2_SUPPORTED = 0x00000004
PDCAP_D3_SUPPORTED = 0x00000008
PDCAP_WAKE_FROM_D0_SUPPORTED = 0x00000010
PDCAP_WAKE_FROM_D1_SUPPORTED = 0x00000020
PDCAP_WAKE_FROM_D2_SUPPORTED = 0x00000040
PDCAP_WAKE_FROM_D3_SUPPORTED = 0x00000080
PDCAP_WARM_EJECT_SUPPORTED = 0x00000100

class CM_Power_Data_s(Structure):
    _fields_ = [('PD_Size', DWORD),
                ('PD_MostRecentPowerState', UINT),
                ('PD_Capabilities', DWORD),
                ('PD_D1Latency', DWORD),
                ('PD_D2Latency', DWORD),
                ('PD_D3Latency', DWORD),
                ('PD_PowerStateMapping', UINT),
                ('PD_DeepestSystemWake', UINT)
    ]

CM_POWER_DATA = CM_Power_Data_s
PCM_POWER_DATA = POINTER(CM_POWER_DATA)

SystemPowerPolicyAc = 0
SystemPowerPolicyDc = 1
VerifySystemPolicyAc = 2
VerifySystemPolicyDc = 3
SystemPowerCapabilities = 4
SystemBatteryState = 5
SystemPowerStateHandler = 6
ProcessorStateHandler = 7
SystemPowerPolicyCurrent = 8
AdministratorPowerPolicy = 9
SystemReserveHiberFile = 10
ProcessorInformation = 11
SystemPowerInformation = 12
ProcessorStateHandler2 = 13
LastWakeTime = 14
LastSleepTime = 15
SystemExecutionState = 16
SystemPowerStateNotifyHandler = 17
ProcessorPowerPolicyAc = 18
ProcessorPowerPolicyDc = 19
VerifyProcessorPowerPolicyAc = 20
VerifyProcessorPowerPolicyDc = 21
ProcessorPowerPolicyCurrent = 22
SystemPowerStateLogging = 23
SystemPowerLoggingEntry = 24
SetPowerSettingValue = 25
NotifyUserPowerSetting = 26
PowerInformationLevelUnused0 = 27
SystemMonitorHiberBootPowerOff = 28
SystemVideoState = 29
TraceApplicationPowerMessage = 30
TraceApplicationPowerMessageEnd = 31
ProcessorPerfStates = 32
ProcessorIdleStates = 33
ProcessorCap = 34
SystemWakeSource = 35
SystemHiberFileInformation = 36
TraceServicePowerMessage = 37
ProcessorLoad = 38
PowerShutdownNotification = 39
MonitorCapabilities = 40
SessionPowerInit = 41
SessionDisplayState = 42
PowerRequestCreate = 43
PowerRequestAction = 44
GetPowerRequestList = 45
ProcessorInformationEx = 46
NotifyUserModeLegacyPowerEvent = 47
GroupPark = 48
ProcessorIdleDomains = 49
WakeTimerList = 50
SystemHiberFileSize = 51
ProcessorIdleStatesHv = 52
ProcessorPerfStatesHv = 53
ProcessorPerfCapHv = 54
ProcessorSetIdle = 55
LogicalProcessorIdling = 56
UserPresence = 57
PowerSettingNotificationName = 58
GetPowerSettingValue = 59
IdleResiliency = 60
SessionRITState = 61
SessionConnectNotification = 62
SessionPowerCleanup = 63
SessionLockState = 64
SystemHiberbootState = 65
PlatformInformation = 66
PdcInvocation = 67
MonitorInvocation = 68
FirmwareTableInformationRegistered = 69
SetShutdownSelectedTime = 70
SuspendResumeInvocation = 71
PlmPowerRequestCreate = 72
ScreenOff = 73
CsDeviceNotification = 74
PlatformRole = 75
LastResumePerformance = 76
DisplayBurst = 77
ExitLatencySamplingPercentage = 78
ApplyLowPowerScenarioSettings = 79
PowerInformationLevelMaximum = 80

class POWER_INFORMATION_LEVEL(enum.IntFlag):
    SystemPowerPolicyAc = 0
    SystemPowerPolicyDc = 1
    VerifySystemPolicyAc = 2
    VerifySystemPolicyDc = 3
    SystemPowerCapabilities = 4
    SystemBatteryState = 5
    SystemPowerStateHandler = 6
    ProcessorStateHandler = 7
    SystemPowerPolicyCurrent = 8
    AdministratorPowerPolicy = 9
    SystemReserveHiberFile = 10
    ProcessorInformation = 11
    SystemPowerInformation = 12
    ProcessorStateHandler2 = 13
    LastWakeTime = 14
    LastSleepTime = 15
    SystemExecutionState = 16
    SystemPowerStateNotifyHandler = 17
    ProcessorPowerPolicyAc = 18
    ProcessorPowerPolicyDc = 19
    VerifyProcessorPowerPolicyAc = 20
    VerifyProcessorPowerPolicyDc = 21
    ProcessorPowerPolicyCurrent = 22
    SystemPowerStateLogging = 23
    SystemPowerLoggingEntry = 24
    SetPowerSettingValue = 25
    NotifyUserPowerSetting = 26
    PowerInformationLevelUnused0 = 27
    SystemMonitorHiberBootPowerOff = 28
    SystemVideoState = 29
    TraceApplicationPowerMessage = 30
    TraceApplicationPowerMessageEnd = 31
    ProcessorPerfStates = 32
    ProcessorIdleStates = 33
    ProcessorCap = 34
    SystemWakeSource = 35
    SystemHiberFileInformation = 36
    TraceServicePowerMessage = 37
    ProcessorLoad = 38
    PowerShutdownNotification = 39
    MonitorCapabilities = 40
    SessionPowerInit = 41
    SessionDisplayState = 42
    PowerRequestCreate = 43
    PowerRequestAction = 44
    GetPowerRequestList = 45
    ProcessorInformationEx = 46
    NotifyUserModeLegacyPowerEvent = 47
    GroupPark = 48
    ProcessorIdleDomains = 49
    WakeTimerList = 50
    SystemHiberFileSize = 51
    ProcessorIdleStatesHv = 52
    ProcessorPerfStatesHv = 53
    ProcessorPerfCapHv = 54
    ProcessorSetIdle = 55
    LogicalProcessorIdling = 56
    UserPresence = 57
    PowerSettingNotificationName = 58
    GetPowerSettingValue = 59
    IdleResiliency = 60
    SessionRITState = 61
    SessionConnectNotification = 62
    SessionPowerCleanup = 63
    SessionLockState = 64
    SystemHiberbootState = 65
    PlatformInformation = 66
    PdcInvocation = 67
    MonitorInvocation = 68
    FirmwareTableInformationRegistered = 69
    SetShutdownSelectedTime = 70
    SuspendResumeInvocation = 71
    PlmPowerRequestCreate = 72
    ScreenOff = 73
    CsDeviceNotification = 74
    PlatformRole = 75
    LastResumePerformance = 76
    DisplayBurst = 77
    ExitLatencySamplingPercentage = 78
    ApplyLowPowerScenarioSettings = 79
    PowerInformationLevelMaximum = 80

UserNotPresent = 0
UserPresent = 1
UserUnknown = 0xff

class POWER_USER_PRESENCE_TYPE(enum.IntFlag):
    UserNotPresent = 0
    UserPresent = 1
    UserUnknown = 0xff

PPOWER_USER_PRESENCE_TYPE = POWER_USER_PRESENCE_TYPE

class _POWER_USER_PRESENCE(Structure):
    _fields_ = [('UserPresence', UINT)]

POWER_USER_PRESENCE = _POWER_USER_PRESENCE
PPOWER_USER_PRESENCE = POINTER(POWER_USER_PRESENCE)

class _POWER_SESSION_CONNECT(Structure):
    _fields_ = [('Connected', BOOLEAN),
                ('Console', BOOLEAN)
    ]

POWER_SESSION_CONNECT = _POWER_SESSION_CONNECT
PPOWER_SESSION_CONNECT = POINTER(POWER_SESSION_CONNECT)

class _POWER_SESSION_TIMEOUTS(Structure):
    _fields_ = [('InputTimeout', DWORD),
                ('DisplayTimeout', DWORD)
    ]

POWER_SESSION_TIMEOUTS = _POWER_SESSION_TIMEOUTS
PPOWER_SESSION_TIMEOUTS = POINTER(POWER_SESSION_TIMEOUTS)

class _POWER_SESSION_RIT_STATE(Structure):
    _fields_ = [('Active', BOOLEAN),
                ('LastInputTime', DWORD)
    ]

POWER_SESSION_RIT_STATE = _POWER_SESSION_RIT_STATE
PPOWER_SESSION_RIT_STATE = POINTER(POWER_SESSION_RIT_STATE)

class _POWER_SESSION_WINLOGON(Structure):
    _fields_ = [('SessionId', DWORD),
                ('Console', BOOLEAN),
                ('Locked', BOOLEAN)
    ]

POWER_SESSION_WINLOGON = _POWER_SESSION_WINLOGON
PPOWER_SESSION_WINLOGON = POINTER(POWER_SESSION_WINLOGON)

class _POWER_IDLE_RESILIENCY(Structure):
    _fields_ = [('CoalescingTimeout', DWORD),
                ('IdleResiliencyPeriod', DWORD)
    ]

POWER_IDLE_RESILIENCY = _POWER_IDLE_RESILIENCY
PPOWER_IDLE_RESILIENCY = POINTER(POWER_IDLE_RESILIENCY)

MonitorRequestReasonUnknown = 0
MonitorRequestReasonPowerButton = 1
MonitorRequestReasonRemoteConnection = 2
MonitorRequestReasonScMonitorpower = 3
MonitorRequestReasonUserInput = 4
MonitorRequestReasonAcDcDisplayBurst = 5
MonitorRequestReasonUserDisplayBurst = 6
MonitorRequestReasonPoSetSystemState = 7
MonitorRequestReasonSetThreadExecutionState = 8
MonitorRequestReasonFullWake = 9
MonitorRequestReasonSessionUnlock = 10
MonitorRequestReasonScreenOffRequest = 11
MonitorRequestReasonIdleTimeout = 12
MonitorRequestReasonPolicyChange = 13
MonitorRequestReasonMax = 14

class POWER_MONITOR_REQUEST_REASON(enum.IntFlag):
    MonitorRequestReasonUnknown = 0
    MonitorRequestReasonPowerButton = 1
    MonitorRequestReasonRemoteConnection = 2
    MonitorRequestReasonScMonitorpower = 3
    MonitorRequestReasonUserInput = 4
    MonitorRequestReasonAcDcDisplayBurst = 5
    MonitorRequestReasonUserDisplayBurst = 6
    MonitorRequestReasonPoSetSystemState = 7
    MonitorRequestReasonSetThreadExecutionState = 8
    MonitorRequestReasonFullWake = 9
    MonitorRequestReasonSessionUnlock = 10
    MonitorRequestReasonScreenOffRequest = 11
    MonitorRequestReasonIdleTimeout = 12
    MonitorRequestReasonPolicyChange = 13
    MonitorRequestReasonMax = 14

class _POWER_MONITOR_INVOCATION(Structure):
    _fields_ = [('On', BOOLEAN),
                ('Console', BOOLEAN),
                ('RequestReason', UINT)
    ]

POWER_MONITOR_INVOCATION = _POWER_MONITOR_INVOCATION
PPOWER_MONITOR_INVOCATION = POINTER(POWER_MONITOR_INVOCATION)

class _RESUME_PERFORMANCE(Structure):
    _fields_ = [('PostTimeMs', DWORD),
                ('TotalResumeTimeMs', ULONGLONG),
                ('ResumeCompleteTimestamp', ULONGLONG),
    ]

RESUME_PERFORMANCE = _RESUME_PERFORMANCE
PRESUME_PERFORMANCE = POINTER(RESUME_PERFORMANCE)

PoAc = 0
PoDc = 1
PoHot = 2
PoConditionMaximum = 3

class SYSTEM_POWER_CONDITION(enum.IntFlag):
    PoAc = 0
    PoDc = 1
    PoHot = 2
    PoConditionMaximum = 3

class SET_POWER_SETTING_VALUE(Structure):
    _fields_ = [('Version', DWORD),
                ('Guid', GUID),
                ('PowerCondition', UINT),
                ('DataLength', DWORD),
                ('Data', BYTE * ANYSIZE_ARRAY)
    ]

PSET_POWER_SETTING_VALUE = POINTER(SET_POWER_SETTING_VALUE)

POWER_SETTING_VALUE_VERSION = 0x1

class NOTIFY_USER_POWER_SETTING(Structure):
    _fields_ = [('Guid', GUID)]

PNOTIFY_USER_POWER_SETTING = POINTER(NOTIFY_USER_POWER_SETTING)

class _APPLICATIONLAUNCH_SETTING_VALUE(Structure):
    _fields_ = [('ActivationTime', LARGE_INTEGER),
                ('Flags', DWORD),
                ('ButtonInstanceID', DWORD),
    ]

APPLICATIONLAUNCH_SETTING_VALUE = _APPLICATIONLAUNCH_SETTING_VALUE
PAPPLICATIONLAUNCH_SETTING_VALUE = POINTER(APPLICATIONLAUNCH_SETTING_VALUE)

PlatformRoleUnspecified = 0
PlatformRoleDesktop = 1
PlatformRoleMobile = 2
PlatformRoleWorkstation = 3
PlatformRoleEnterpriseServer = 4
PlatformRoleSOHOServer = 5
PlatformRoleAppliancePC = 6
PlatformRolePerformanceServer = 7
PlatformRoleSlate = 8
PlatformRoleMaximum = 9

class _POWER_PLATFORM_ROLE(enum.IntFlag):
    PlatformRoleUnspecified = 0
    PlatformRoleDesktop = 1
    PlatformRoleMobile = 2
    PlatformRoleWorkstation = 3
    PlatformRoleEnterpriseServer = 4
    PlatformRoleSOHOServer = 5
    PlatformRoleAppliancePC = 6
    PlatformRolePerformanceServer = 7
    PlatformRoleSlate = 8
    PlatformRoleMaximum = 9

POWER_PLATFORM_ROLE = _POWER_PLATFORM_ROLE
PPOWER_PLATFORM_ROLE = POWER_PLATFORM_ROLE

class _POWER_PLATFORM_INFORMATION(Structure):
    _fields_ = [('AoAc', BOOLEAN)]

POWER_PLATFORM_INFORMATION = _POWER_PLATFORM_INFORMATION
PPOWER_PLATFORM_INFORMATION = POINTER(POWER_PLATFORM_INFORMATION)

POWER_PLATFORM_ROLE_V1 = 0x00000001
POWER_PLATFORM_ROLE_V1_MAX = PlatformRolePerformanceServer + 1

POWER_PLATFORM_ROLE_V2 = 0x00000002
POWER_PLATFORM_ROLE_V2_MAX = PlatformRoleSlate + 1

if WIN32_WINNT >= 0x0602:
    POWER_PLATFORM_ROLE_VERSION = POWER_PLATFORM_ROLE_V2
    POWER_PLATFORM_ROLE_VERSION_MAX = POWER_PLATFORM_ROLE_V2_MAX
else:
    POWER_PLATFORM_ROLE_VERSION = POWER_PLATFORM_ROLE_V1
    POWER_PLATFORM_ROLE_VERSION_MAX = POWER_PLATFORM_ROLE_V1_MAX

class BATTERY_REPORTING_SCALE(Structure):
    _fields_ = [('Granularity', DWORD),
                ('Capacity', DWORD)
    ]

PBATTERY_REPORTING_SCALE = POINTER(BATTERY_REPORTING_SCALE)

class PPM_WMI_LEGACY_PERFSTATE(Structure):
    _fields_ = [('Frequency', DWORD),
                ('Flags', DWORD),
                ('PercentFrequency', DWORD)
    ]

PPPM_WMI_LEGACY_PERFSTATE = POINTER(PPM_WMI_LEGACY_PERFSTATE)

class PPM_WMI_IDLE_STATE(Structure):
    _fields_ = [('Latency', DWORD),
                ('Power', DWORD),
                ('TimeCheck', DWORD),
                ('PromotePercent', BYTE),
                ('DemotePercent', BYTE),
                ('StateType', BYTE),
                ('Reserved', BYTE),
                ('StateFlags', DWORD),
                ('Context', DWORD),
                ('IdleHandler', DWORD),
                ('Reserved1', DWORD)
    ]

PPPM_WMI_IDLE_STATE = POINTER(PPM_WMI_IDLE_STATE)

class PPM_WMI_IDLE_STATES(Structure):
    _fields_ = [('Type', DWORD),
                ('Count', DWORD),
                ('TargetState', DWORD),
                ('OldState', DWORD),
                ('TargetProcessors', DWORD64),
                ('State', PPM_WMI_IDLE_STATE * ANYSIZE_ARRAY)
    ]

PPPM_WMI_IDLE_STATES = POINTER(PPM_WMI_IDLE_STATES)

class PPM_WMI_IDLE_STATES_EX(Structure):
    _fields_ = [('Type', DWORD),
                ('Count', DWORD),
                ('TargetState', DWORD),
                ('OldState', DWORD),
                ('TargetProcessors', PVOID),
                ('State', PPM_WMI_IDLE_STATE * ANYSIZE_ARRAY)
    ]

PPPM_WMI_IDLE_STATES_EX = POINTER(PPM_WMI_IDLE_STATES_EX)

class PPM_WMI_PERF_STATE(Structure):
    _fields_ = [('Frequency', DWORD),
                ('Power', DWORD),
                ('PercentFrequency', BYTE),
                ('IncreaseLevel', BYTE),
                ('DecreaseLevel', BYTE),
                ('Type', BYTE),
                ('IncreaseTime', DWORD),
                ('DecreaseTime', DWORD),
                ('Control', DWORD64),
                ('Status', DWORD64),
                ('HitCount', DWORD),
                ('Reserved1', DWORD),
                ('Reserved2', DWORD64),
                ('Reserved3', DWORD64)
    ]

PPPM_WMI_PERF_STATE = POINTER(PPM_WMI_PERF_STATE)

class PPM_WMI_PERF_STATES(Structure):
    _fields_ = [('Count', DWORD),
                ('MaxFrequency', DWORD),
                ('CurrentState', DWORD),
                ('MaxPerfState', DWORD),
                ('MinPerfState', DWORD),
                ('LowestPerfState', DWORD),
                ('ThermalConstraint', DWORD),
                ('BusyAdjThreshold', BYTE),
                ('PolicyType', BYTE),
                ('Type', BYTE),
                ('Reserved', BYTE),
                ('TimerInterval', DWORD),
                ('TargetProcessors', DWORD64),
                ('PStateHandler', DWORD),
                ('PStateContext', DWORD),
                ('TStateHandler', DWORD),
                ('TStateContext', DWORD),
                ('FeedbackHandler', DWORD),
                ('Reserved1', DWORD),
                ('Reserved2', DWORD64),
                ('State', PPM_WMI_PERF_STATE * ANYSIZE_ARRAY)
    ]

PPPM_WMI_PERF_STATES = POINTER(PPM_WMI_PERF_STATES)

class PPM_WMI_PERF_STATES_EX(Structure):
    _fields_ = [('Count', DWORD),
                ('MaxFrequency', DWORD),
                ('CurrentState', DWORD),
                ('MaxPerfState', DWORD),
                ('MinPerfState', DWORD),
                ('LowestPerfState', DWORD),
                ('ThermalConstraint', DWORD),
                ('BusyAdjThreshold', BYTE),
                ('PolicyType', BYTE),
                ('Type', BYTE),
                ('Reserved', BYTE),
                ('TimerInterval', DWORD),
                ('TargetProcessors', PVOID),
                ('PStateHandler', DWORD),
                ('PStateContext', DWORD),
                ('TStateHandler', DWORD),
                ('TStateContext', DWORD),
                ('FeedbackHandler', DWORD),
                ('Reserved1', DWORD),
                ('Reserved2', DWORD64),
                ('State', PPM_WMI_PERF_STATE * ANYSIZE_ARRAY)
    ]

PPPM_WMI_PERF_STATES_EX = POINTER(PPM_WMI_PERF_STATES_EX)

PROC_IDLE_BUCKET_COUNT = 6
PROC_IDLE_BUCKET_COUNT_EX = 16

class PPM_IDLE_STATE_ACCOUNTING(Structure):
    _fields_ = [('IdleTransitions', DWORD),
                ('FailedTransitions', DWORD),
                ('InvalidBucketIndex', DWORD),
                ('TotalTime', DWORD64),
                ('IdleTimeBuckets', DWORD * PROC_IDLE_BUCKET_COUNT)
    ]

PPPM_IDLE_STATE_ACCOUNTING = POINTER(PPM_IDLE_STATE_ACCOUNTING)

class PPM_IDLE_ACCOUNTING(Structure):
    _fields_ = [('StateCount', DWORD),
                ('TotalTransitions', DWORD),
                ('ResetCount', DWORD),
                ('StartTime', DWORD64),
                ('State', PPM_IDLE_STATE_ACCOUNTING * ANYSIZE_ARRAY)
    ]

PPPM_IDLE_ACCOUNTING = POINTER(PPM_IDLE_ACCOUNTING)

class PPM_IDLE_STATE_BUCKET_EX(Structure):
    _fields_ = [('TotalTimeUs', DWORD64),
                ('MinTimeUs', DWORD),
                ('MaxTimeUs', DWORD),
                ('Count', DWORD)
    ]

PPPM_IDLE_STATE_BUCKET_EX = POINTER(PPM_IDLE_STATE_BUCKET_EX)

class PPM_IDLE_STATE_ACCOUNTING_EX(Structure):
    _fields_ = [('TotalTime', DWORD64),
                ('IdleTransitions', DWORD),
                ('FailedTransitions', DWORD),
                ('InvalidBucketIndex', DWORD),
                ('MinTimeUs', DWORD),
                ('MaxTimeUs', DWORD),
                ('CancelledTransitions', DWORD),
                ('IdleTimeBuckets', PPM_IDLE_STATE_BUCKET_EX * PROC_IDLE_BUCKET_COUNT_EX)
    ]

PPPM_IDLE_STATE_ACCOUNTING_EX = POINTER(PPM_IDLE_STATE_ACCOUNTING_EX)

class PPM_IDLE_ACCOUNTING_EX(Structure):
    _fields_ = [('StateCount', DWORD),
                ('TotalTransitions', DWORD),
                ('ResetCount', DWORD),
                ('AbortCount', DWORD),
                ('StartTime', DWORD64),
                ('State', PPM_IDLE_STATE_ACCOUNTING_EX * ANYSIZE_ARRAY)
    ]

PPPM_IDLE_ACCOUNTING_EX = POINTER(PPM_IDLE_ACCOUNTING_EX)

ACPI_PPM_SOFTWARE_ALL = 0xfc
ACPI_PPM_SOFTWARE_ANY = 0xfd
ACPI_PPM_HARDWARE_ALL = 0xfe

MS_PPM_SOFTWARE_ALL = 0x1

PPM_FIRMWARE_ACPI1C2 = 0x1
PPM_FIRMWARE_ACPI1C3 = 0x2
PPM_FIRMWARE_ACPI1TSTATES = 0x4
PPM_FIRMWARE_CST = 0x8
PPM_FIRMWARE_CSD = 0x10
PPM_FIRMWARE_PCT = 0x20
PPM_FIRMWARE_PSS = 0x40
PPM_FIRMWARE_XPSS = 0x80
PPM_FIRMWARE_PPC = 0x100
PPM_FIRMWARE_PSD = 0x200
PPM_FIRMWARE_PTC = 0x400
PPM_FIRMWARE_TSS = 0x800
PPM_FIRMWARE_TPC = 0x1000
PPM_FIRMWARE_TSD = 0x2000
PPM_FIRMWARE_PCCH = 0x4000
PPM_FIRMWARE_PCCP = 0x8000
PPM_FIRMWARE_OSC = 0x10000
PPM_FIRMWARE_PDC = 0x20000
PPM_FIRMWARE_CPC = 0x40000

PPM_PERFORMANCE_IMPLEMENTATION_NONE = 0
PPM_PERFORMANCE_IMPLEMENTATION_PSTATES = 1
PPM_PERFORMANCE_IMPLEMENTATION_PCCV1 = 2
PPM_PERFORMANCE_IMPLEMENTATION_CPPC = 3
PPM_PERFORMANCE_IMPLEMENTATION_PEP = 4

PPM_IDLE_IMPLEMENTATION_NONE = 0x0
PPM_IDLE_IMPLEMENTATION_CSTATES = 0x1
PPM_IDLE_IMPLEMENTATION_PEP = 0x2

class PPM_PERFSTATE_EVENT(Structure):
    _fields_ = [('State', DWORD),
                ('Status', DWORD),
                ('Latency', DWORD),
                ('Speed', DWORD),
                ('Processor', DWORD)
    ]

PPPM_PERFSTATE_EVENT = POINTER(PPM_PERFSTATE_EVENT)

class PPM_PERFSTATE_DOMAIN_EVENT(Structure):
    _fields_ = [('State', DWORD),
                ('Latency', DWORD),
                ('Speed', DWORD),
                ('Processors', DWORD64)
    ]

PPPM_PERFSTATE_DOMAIN_EVENT = POINTER(PPM_PERFSTATE_DOMAIN_EVENT)

class PPM_IDLESTATE_EVENT(Structure):
    _fields_ = [('NewState', DWORD),
                ('OldState', DWORD),
                ('Processors', DWORD64)
    ]

PPPM_IDLESTATE_EVENT = POINTER(PPM_IDLESTATE_EVENT)

class PPM_THERMALCHANGE_EVENT(Structure):
    _fields_ = [('ThermalConstraint', DWORD),
                ('Processors', DWORD64)
    ]

PPPM_THERMALCHANGE_EVENT = POINTER(PPM_THERMALCHANGE_EVENT)

class PPM_THERMAL_POLICY_EVENT(Structure):
    _fields_ = [('Mode', BYTE),
                ('Processors', DWORD64)
    ]

PPPM_THERMAL_POLICY_EVENT = POINTER(PPM_THERMAL_POLICY_EVENT)

PPM_PERFSTATE_CHANGE_GUID = DEFINE_GUID(0xa5b32ddd, 0x7f39, 0x4abc, 0xb8, 0x92, 0x90, 0xe, 0x43, 0xb5, 0x9e, 0xbb)
PPM_PERFSTATE_DOMAIN_CHANGE_GUID = DEFINE_GUID(0x995e6b7f, 0xd653, 0x497a, 0xb9, 0x78, 0x36, 0xa3, 0xc, 0x29, 0xbf, 0x1)
PPM_IDLESTATE_CHANGE_GUID = DEFINE_GUID(0x4838fe4f, 0xf71c, 0x4e51, 0x9e, 0xcc, 0x84, 0x30, 0xa7, 0xac, 0x4c, 0x6c)
PPM_PERFSTATES_DATA_GUID = DEFINE_GUID(0x5708cc20, 0x7d40, 0x4bf4, 0xb4, 0xaa, 0x2b, 0x01, 0x33, 0x8d, 0x01, 0x26)
PPM_IDLESTATES_DATA_GUID = DEFINE_GUID(0xba138e10, 0xe250, 0x4ad7, 0x86, 0x16, 0xcf, 0x1a, 0x7a, 0xd4, 0x10, 0xe7)
PPM_IDLE_ACCOUNTING_GUID = DEFINE_GUID(0xe2a26f78, 0xae07, 0x4ee0, 0xa3, 0x0f, 0xce, 0x54, 0xf5, 0x5a, 0x94, 0xcd)
PPM_IDLE_ACCOUNTING_EX_GUID = DEFINE_GUID(0xd67abd39, 0x81f8, 0x4a5e, 0x81, 0x52, 0x72, 0xe3, 0x1e, 0xc9, 0x12, 0xee)
PPM_THERMALCONSTRAINT_GUID = DEFINE_GUID(0xa852c2c8, 0x1a4c, 0x423b, 0x8c, 0x2c, 0xf3, 0x0d, 0x82, 0x93, 0x1a, 0x88)
PPM_PERFMON_PERFSTATE_GUID = DEFINE_GUID(0x7fd18652, 0xcfe, 0x40d2, 0xb0, 0xa1, 0xb, 0x6, 0x6a, 0x87, 0x75, 0x9e)
PPM_THERMAL_POLICY_CHANGE_GUID = DEFINE_GUID(0x48f377b8, 0x6880, 0x4c7b, 0x8b, 0xdc, 0x38, 0x1, 0x76, 0xc6, 0x65, 0x4d)

class POWER_ACTION_POLICY(Structure):
    _fields_ = [('Action', UINT),
                ('Flags', DWORD),
                ('EventCode', DWORD)
    ]

PPOWER_ACTION_POLICY = POINTER(POWER_ACTION_POLICY)

POWER_ACTION_QUERY_ALLOWED = 0x00000001
POWER_ACTION_UI_ALLOWED = 0x00000002
POWER_ACTION_OVERRIDE_APPS = 0x00000004
POWER_ACTION_HIBERBOOT = 0x00000008
POWER_ACTION_PSEUDO_TRANSITION = 0x08000000
POWER_ACTION_LIGHTEST_FIRST = 0x10000000
POWER_ACTION_LOCK_CONSOLE = 0x20000000
POWER_ACTION_DISABLE_WAKES = 0x40000000
POWER_ACTION_CRITICAL = 0x80000000

POWER_LEVEL_USER_NOTIFY_TEXT = 0x00000001
POWER_LEVEL_USER_NOTIFY_SOUND = 0x00000002
POWER_LEVEL_USER_NOTIFY_EXEC = 0x00000004
POWER_USER_NOTIFY_BUTTON = 0x00000008
POWER_USER_NOTIFY_SHUTDOWN = 0x00000010
POWER_USER_NOTIFY_FORCED_SHUTDOWN = 0x00000020
POWER_FORCE_TRIGGER_RESET = 0x80000000

BATTERY_DISCHARGE_FLAGS_EVENTCODE_MASK = 0x00000007
BATTERY_DISCHARGE_FLAGS_ENABLE = 0x80000000

DISCHARGE_POLICY_CRITICAL = 0
DISCHARGE_POLICY_LOW = 1

NUM_DISCHARGE_POLICIES = 4

PROCESSOR_IDLESTATE_POLICY_COUNT = 0x3

class PROCESSOR_IDLESTATE_INFO(Structure):
    _fields_ = [('TimeCheck', DWORD),
                ('DemotePercent', BYTE),
                ('PromotePercent', BYTE),
                ('Spare', BYTE * 2),
    ]

PPROCESSOR_IDLESTATE_INFO = POINTER(PROCESSOR_IDLESTATE_INFO)

class SYSTEM_POWER_LEVEL(Structure):
    _fields_ = [('Enable', BOOLEAN),
                ('Spare', BYTE),
                ('BatteryLevel', DWORD),
                ('PowerPolicy', POWER_ACTION_POLICY),
                ('MinSystemState', UINT)
    ]

PSYSTEM_POWER_LEVEL = POINTER(SYSTEM_POWER_LEVEL)

class _SYSTEM_POWER_POLICY(Structure):
    _fields_ = [('Revision', DWORD),
                ('PowerButton', POWER_ACTION_POLICY),
                ('SleepButton', POWER_ACTION_POLICY),
                ('LidClose', POWER_ACTION_POLICY),
                ('LidOpenWake', UINT),
                ('Reserved', DWORD),
                ('Idle', POWER_ACTION_POLICY),
                ('IdleTimeout', DWORD),
                ('IdleSensitivity', BYTE),
                ('DynamicThrottle', BYTE),
                ('Spare2', BYTE * 2),
                ('MinSleep', UINT),
                ('MaxSleep', UINT),
                ('ReducedLatencySleep', UINT),
                ('WinLogonFlags', DWORD),
                ('Spare3', DWORD),
                ('DozeS4Timeout', DWORD),
                ('BroadcastCapacityResolution', DWORD),
                ('DischargePolicy', SYSTEM_POWER_LEVEL * NUM_DISCHARGE_POLICIES),
                ('VideoTimeout', DWORD),
                ('VideoDimDisplay', BOOLEAN),
                ('VideoReserved', DWORD),
                ('SpindownTimeout', DWORD),
                ('OptimizeForPower', BOOLEAN),
                ('FanThrottleTolerance', BYTE),
                ('ForcedThrottle', BYTE),
                ('MinThrottle', BYTE),
                ('OverThrottled', POWER_ACTION_POLICY)
    ]

SYSTEM_POWER_POLICY = _SYSTEM_POWER_POLICY
PSYSTEM_POWER_POLICY = POINTER(SYSTEM_POWER_POLICY)

PO_THROTTLE_NONE = 0
PO_THROTTLE_CONSTANT = 1
PO_THROTTLE_DEGRADE = 2
PO_THROTTLE_ADAPTIVE = 3
PO_THROTTLE_MAXIMUM = 4

class PROCESSOR_IDLESTATE_POLICY(Structure):
    class Flags(Union):
        class DUMMYSTRUCTNAME(LittleEndianStructure):
            _fields_ = [('AllowScaling', WORD, 1),
                        ('Disabled', WORD, 1),
                        ('Reserved', WORD, 14)
            ]
        
        _anonymous_ = ['DUMMYSTRUCTNAME']
        _fields_ = [('AsWORD', WORD),
                    ('DUMMYSTRUCTNAME', DUMMYSTRUCTNAME)
        ]
    
    _anonymous_ = ['Flags']
    _fields_ = [('Revision', WORD),
                ('Flags', Flags),
                ('PolicyCount', DWORD),
                ('Policy', PROCESSOR_IDLESTATE_INFO * PROCESSOR_IDLESTATE_POLICY_COUNT)
    ]

PPROCESSOR_IDLESTATE_POLICY = POINTER(PROCESSOR_IDLESTATE_POLICY)

class _PROCESSOR_POWER_POLICY_INFO(Structure):
    _fields_ = [('TimeCheck', DWORD),
                ('DemoteLimit', DWORD),
                ('PromoteLimit', DWORD),
                ('DemotePercent', BYTE),
                ('PromotePercent', BYTE),
                ('Spare', BYTE),
                ('AllowDemotion', DWORD, 1),
                ('AllowPromotion', DWORD, 1),
                ('Reserved', DWORD, 30)
    ]

PROCESSOR_POWER_POLICY_INFO = _PROCESSOR_POWER_POLICY_INFO
PPROCESSOR_POWER_POLICY_INFO = POINTER(PROCESSOR_POWER_POLICY_INFO)

class _PROCESSOR_POWER_POLICY(Structure):
    _fields_ = [('Revision', DWORD),
                ('DynamicThrottle', BYTE),
                ('Spare', BYTE * 3),
                ('DisableCStates', DWORD, 1),
                ('Reserved', DWORD, 31),
                ('PolicyCount', DWORD),
                ('Policy', PROCESSOR_POWER_POLICY_INFO * 3)
    ]

PROCESSOR_POWER_POLICY = _PROCESSOR_POWER_POLICY
PPROCESSOR_POWER_POLICY = POINTER(PROCESSOR_POWER_POLICY)

class PROCESSOR_PERFSTATE_POLICY(Structure):
    class DUMMYUNIONNAME(Union):
        class Flags(Union):
            class NoIncDecResLittleStruct(LittleEndianStructure):
                _fields_ = [('NoDomainAccounting', BYTE, 1),
                            ('IncreasePolicy', BYTE, 2),
                            ('DecreasePolicy', BYTE, 2),
                            ('Reserved', BYTE, 3)
                ]
            
            _anonymous_ = ['NoIncDecResLittleStruct']
            _fields_ = [('AsBYTE', BYTE),
                        ('NoIncDecResLittleStruct', NoIncDecResLittleStruct)
            ]
        
        _anonymous_ = ['Flags']
        _fields_ = [('Spare', BYTE), 
                    ('Flags', Flags)
        ]
    
    _anonymous_ = ['DUMMYUNIONNAME']
    _fields_ = [('Revision', DWORD),
                ('MaxThrottle', BYTE),
                ('MinThrottle', BYTE),
                ('BusyAdjThreshold', BYTE),
                ('DUMMYUNIONNAME', DUMMYUNIONNAME),
                ('TimeCheck', DWORD),
                ('IncreaseTime', DWORD),
                ('DecreaseTime', DWORD),
                ('IncreasePercent', DWORD),
                ('DecreasePercent', DWORD)
    ]

PPROCESSOR_PERFSTATE_POLICY = POINTER(PROCESSOR_PERFSTATE_POLICY)

class _ADMINISTRATOR_POWER_POLICY(Structure):
    _fields_ = [('MinSleep', UINT),
                ('MaxSleep', UINT),
                ('MinVideoTimeout', DWORD),
                ('MaxVideoTimeout', DWORD),
                ('MinSpindownTimeout', DWORD),
                ('MaxSpindownTimeout', DWORD)
    ]

ADMINISTRATOR_POWER_POLICY = _ADMINISTRATOR_POWER_POLICY
PADMINISTRATOR_POWER_POLICY = POINTER(ADMINISTRATOR_POWER_POLICY)

class SYSTEM_POWER_CAPABILITIES(Structure):
    _fields_ = [('PowerButtonPresent', BOOLEAN),
                ('SleepButtonPresent', BOOLEAN),
                ('LidPresent', BOOLEAN),
                ('SystemS1', BOOLEAN),
                ('SystemS2', BOOLEAN),
                ('SystemS3', BOOLEAN),
                ('SystemS4', BOOLEAN),
                ('SystemS5', BOOLEAN),
                ('HiberFilePresent', BOOLEAN),
                ('FullWake', BOOLEAN),
                ('VideoDimPresent', BOOLEAN),
                ('ApmPresent', BOOLEAN),
                ('UpsPresent', BOOLEAN),
                ('ThermalControl', BOOLEAN),
                ('ProcessorThrottle', BOOLEAN),
                ('ProcessorMinThrottle', BYTE),
                ('ProcessorMaxThrottle', BYTE),
                ('FastSystemS4', BOOLEAN),
                ('spare2', BYTE * 3),
                ('DiskSpinDown', BOOLEAN),
                ('spare3', BYTE * 8),
                ('SystemBatteriesPresent', BOOLEAN),
                ('BatteriesAreShortTerm', BOOLEAN),
                ('BatteryScale', BATTERY_REPORTING_SCALE * 3),
                ('AcOnLineWake', UINT),
                ('SoftLidWake', UINT),
                ('RtcWake', UINT),
                ('MinDeviceWakeState', UINT),
                ('DefaultLowLatencyWake', UINT)
    ]

PSYSTEM_POWER_CAPABILITIES = POINTER(SYSTEM_POWER_CAPABILITIES)

class SYSTEM_BATTERY_STATE(Structure):
    _fields_ = [('AcOnLine', BOOLEAN),
                ('BatteryPresent', BOOLEAN),
                ('Charging', BOOLEAN),
                ('Discharging', BOOLEAN),
                ('Spare1', BOOLEAN * 4),
                ('MaxCapacity', DWORD),
                ('RemainingCapacity', DWORD),
                ('Rate', DWORD),
                ('EstimatedTime', DWORD),
                ('DefaultAlert1', DWORD),
                ('DefaultAlert2', DWORD)
    ]

PSYSTEM_BATTERY_STATE = POINTER(SYSTEM_BATTERY_STATE)

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_OS2_SIGNATURE = 0x454E
IMAGE_OS2_SIGNATURE_LE = 0x454C
IMAGE_VXD_SIGNATURE = 0x454C
IMAGE_NT_SIGNATURE = 0x00004550

class _IMAGE_DOS_HEADER(Structure):
    _fields_ = [('e_magic', WORD),
                ('e_cblp', WORD),
                ('e_cp', WORD),
                ('e_crlc', WORD),
                ('e_cparhdr', WORD),
                ('e_minalloc', WORD),
                ('e_maxalloc', WORD),
                ('e_ss', WORD),
                ('e_sp', WORD),
                ('e_csum', WORD),
                ('e_ip', WORD),
                ('e_cs', WORD),
                ('e_lfarlc', WORD),
                ('e_ovno', WORD),
                ('e_res', WORD * 4),
                ('e_oemid', WORD),
                ('e_oeminfo', WORD),
                ('e_res2', WORD * 10),
                ('e_lfanew', LONG)
    ]

IMAGE_DOS_HEADER = _IMAGE_DOS_HEADER
PIMAGE_DOS_HEADER = POINTER(IMAGE_DOS_HEADER)

class _IMAGE_OS2_HEADER(Structure):
    _fields_ = [('ne_magic', WORD),
                ('ne_ver', CHAR),
                ('ne_rev', CHAR),
                ('ne_enttab', WORD),
                ('ne_cbenttab', WORD),
                ('ne_crc', LONG),
                ('ne_flags', WORD),
                ('ne_autodata', WORD),
                ('ne_heap', WORD),
                ('ne_stack', WORD),
                ('ne_csip', LONG),
                ('ne_sssp', LONG),
                ('ne_cseg', WORD),
                ('ne_cmod', WORD),
                ('ne_cbnrestab', WORD),
                ('ne_segtab', WORD),
                ('ne_rsrctab', WORD),
                ('ne_restab', WORD),
                ('ne_modtab', WORD),
                ('ne_imptab', WORD),
                ('ne_nrestab', LONG),
                ('ne_cmovent', WORD),
                ('ne_align', WORD),
                ('ne_cres', WORD),
                ('ne_exetyp', BYTE),
                ('ne_flagsothers', BYTE),
                ('ne_pretthunks', WORD),
                ('ne_psegrefbytes', WORD),
                ('ne_swaparea', WORD),
                ('ne_expver', WORD)
    ]

IMAGE_OS2_HEADER = _IMAGE_OS2_HEADER
PIMAGE_OS2_HEADER = POINTER(IMAGE_OS2_HEADER)

class _IMAGE_VXD_HEADER(Structure):
    _fields_ = [('e32_magic', WORD),
                ('e32_border', BYTE),
                ('e32_worder', BYTE),
                ('e32_level', DWORD),
                ('e32_cpu', WORD),
                ('e32_os', WORD),
                ('e32_ver', DWORD),
                ('e32_mflags', DWORD),
                ('e32_mpages', DWORD),
                ('e32_startobj', DWORD),
                ('e32_eip', DWORD),
                ('e32_stackobj', DWORD),
                ('e32_esp', DWORD),
                ('e32_pagesize', DWORD),
                ('e32_lastpagesize', DWORD),
                ('e32_fixupsize', DWORD),
                ('e32_fixupsum', DWORD),
                ('e32_ldrsize', DWORD),
                ('e32_ldrsum', DWORD),
                ('e32_objtab', DWORD),
                ('e32_objcnt', DWORD),
                ('e32_objmap', DWORD),
                ('e32_itermap', DWORD),
                ('e32_rsrctab', DWORD),
                ('e32_rsrccnt', DWORD),
                ('e32_restab', DWORD),
                ('e32_enttab', DWORD),
                ('e32_dirtab', DWORD),
                ('e32_dircnt', DWORD),
                ('e32_fpagetab', DWORD),
                ('e32_frectab', DWORD),
                ('e32_impmod', DWORD),
                ('e32_impmodcnt', DWORD),
                ('e32_impproc', DWORD),
                ('e32_pagesum', DWORD),
                ('e32_datapage', DWORD),
                ('e32_preload', DWORD),
                ('e32_nrestab', DWORD),
                ('e32_cbnrestab', DWORD),
                ('e32_nressum', DWORD),
                ('e32_autodata', DWORD),
                ('e32_debuginfo', DWORD),
                ('e32_debuglen', DWORD),
                ('e32_instpreload', DWORD),
                ('e32_instdemand', DWORD),
                ('e32_heapsize', DWORD),
                ('e32_res3', BYTE * 12),
                ('e32_winresoff', DWORD),
                ('e32_winreslen', DWORD),
                ('e32_devid', WORD),
                ('e32_ddkver', WORD)
    ]

IMAGE_VXD_HEADER = _IMAGE_VXD_HEADER
PIMAGE_VXD_HEADER = POINTER(IMAGE_VXD_HEADER)

class _IMAGE_FILE_HEADER(Structure):
    _fields_ = [('Machine', WORD),
                ('NumberOfSections', WORD),
                ('TimeDateStamp', DWORD),
                ('PointerToSymbolTable', DWORD),
                ('NumberOfSymbols', DWORD),
                ('SizeOfOptionalHeader', WORD),
                ('Characteristics', WORD)
    ]

IMAGE_FILE_HEADER = _IMAGE_FILE_HEADER
PIMAGE_FILE_HEADER = POINTER(IMAGE_FILE_HEADER)

IMAGE_SIZEOF_FILE_HEADER = 20

IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_BYTES_REVERSED_LO = 0x0080
IMAGE_FILE_32BIT_MACHINE = 0x0100
IMAGE_FILE_DEBUG_STRIPPED = 0x0200
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800
IMAGE_FILE_SYSTEM = 0x1000
IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
IMAGE_FILE_BYTES_REVERSED_HI = 0x8000

IMAGE_FILE_MACHINE_UNKNOWN = 0
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_R3000 = 0x0162
IMAGE_FILE_MACHINE_R4000 = 0x0166
IMAGE_FILE_MACHINE_R10000 = 0x0168
IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169
IMAGE_FILE_MACHINE_ALPHA = 0x0184
IMAGE_FILE_MACHINE_SH3 = 0x01a2
IMAGE_FILE_MACHINE_SH3DSP = 0x01a3
IMAGE_FILE_MACHINE_SH3E = 0x01a4
IMAGE_FILE_MACHINE_SH4 = 0x01a6
IMAGE_FILE_MACHINE_SH5 = 0x01a8
IMAGE_FILE_MACHINE_ARM = 0x01c0
IMAGE_FILE_MACHINE_ARMV7 = 0x01c4
IMAGE_FILE_MACHINE_ARMNT = 0x01c4
IMAGE_FILE_MACHINE_ARM64 = 0xaa64
IMAGE_FILE_MACHINE_THUMB = 0x01c2
IMAGE_FILE_MACHINE_AM33 = 0x01d3
IMAGE_FILE_MACHINE_POWERPC = 0x01F0
IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1
IMAGE_FILE_MACHINE_IA64 = 0x0200
IMAGE_FILE_MACHINE_MIPS16 = 0x0266
IMAGE_FILE_MACHINE_ALPHA64 = 0x0284
IMAGE_FILE_MACHINE_MIPSFPU = 0x0366
IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466
IMAGE_FILE_MACHINE_AXP64 = IMAGE_FILE_MACHINE_ALPHA64
IMAGE_FILE_MACHINE_TRICORE = 0x0520
IMAGE_FILE_MACHINE_CEF = 0x0CEF
IMAGE_FILE_MACHINE_EBC = 0x0EBC
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_M32R = 0x9041
IMAGE_FILE_MACHINE_CEE = 0xc0ee

class _IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [('VirtualAddress', DWORD),
                ('Size', DWORD)
    ]

IMAGE_DATA_DIRECTORY = _IMAGE_DATA_DIRECTORY
PIMAGE_DATA_DIRECTORY = POINTER(IMAGE_DATA_DIRECTORY)

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

class _IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [('Magic', WORD),
                ('MajorLinkerVersion', BYTE),
                ('MinorLinkerVersion', BYTE),
                ('SizeOfCode', DWORD),
                ('SizeOfInitializedData', DWORD),
                ('SizeOfUninitializedData', DWORD),
                ('AddressOfEntryPoint', DWORD),
                ('BaseOfCode', DWORD),
                ('BaseOfData', DWORD),
                ('ImageBase', DWORD),
                ('SectionAlignment', DWORD),
                ('FileAlignment', DWORD),
                ('MajorOperatingSystemVersion', WORD),
                ('MinorOperatingSystemVersion', WORD),
                ('MajorImageVersion', WORD),
                ('MinorImageVersion', WORD),
                ('MajorSubsystemVersion', WORD),
                ('MinorSubsystemVersion', WORD),
                ('Win32VersionValue', DWORD),
                ('SizeOfImage', DWORD),
                ('SizeOfHeaders', DWORD),
                ('CheckSum', DWORD),
                ('Subsystem', WORD),
                ('DllCharacteristics', WORD),
                ('SizeOfStackReserve', DWORD),
                ('SizeOfStackCommit', DWORD),
                ('SizeOfHeapReserve', DWORD),
                ('SizeOfHeapCommit', DWORD),
                ('LoaderFlags', DWORD),
                ('NumberOfRvaAndSizes', DWORD),
                ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    ]

IMAGE_OPTIONAL_HEADER32 = _IMAGE_OPTIONAL_HEADER
PIMAGE_OPTIONAL_HEADER32 = POINTER(IMAGE_OPTIONAL_HEADER32)

class _IMAGE_ROM_OPTIONAL_HEADER(Structure):
    _fields_ = [('Magic', WORD),
                ('MajorLinkerVersion', BYTE),
                ('MinorLinkerVersion', BYTE),
                ('SizeOfCode', DWORD),
                ('SizeOfInitializedData', DWORD),
                ('SizeOfUninitializedData', DWORD),
                ('AddressOfEntryPoint', DWORD),
                ('BaseOfCode', DWORD),
                ('BaseOfData', DWORD),
                ('BaseOfBss', DWORD),
                ('GprMask', DWORD),
                ('CprMask', DWORD * 4),
                ('GpValue',DWORD)
    ]

IMAGE_ROM_OPTIONAL_HEADER = _IMAGE_ROM_OPTIONAL_HEADER
PIMAGE_ROM_OPTIONAL_HEADER = POINTER(IMAGE_ROM_OPTIONAL_HEADER)

class _IMAGE_OPTIONAL_HEADER64(Structure):
    _fields_ = [('Magic', WORD),
                ('MajorLinkerVersion', BYTE),
                ('MinorLinkerVersion', BYTE),
                ('SizeOfCode', DWORD),
                ('SizeOfInitializedData', DWORD),
                ('SizeOfUninitializedData', DWORD),
                ('AddressOfEntryPoint', DWORD),
                ('BaseOfCode', DWORD),
                ('ImageBase', ULONGLONG),
                ('SectionAlignment', DWORD),
                ('FileAlignment', DWORD),
                ('MajorOperatingSystemVersion', WORD),
                ('MinorOperatingSystemVersion', WORD),
                ('MajorImageVersion', WORD),
                ('MinorImageVersion', WORD),
                ('MajorSubsystemVersion', WORD),
                ('MinorSubsystemVersion', WORD),
                ('Win32VersionValue', DWORD),
                ('SizeOfImage', DWORD),
                ('SizeOfHeaders', DWORD),
                ('CheckSum', DWORD),
                ('Subsystem', WORD),
                ('DllCharacteristics', WORD),
                ('SizeOfStackReserve', ULONGLONG),
                ('SizeOfStackCommit', ULONGLONG),
                ('SizeOfHeapReserve', ULONGLONG),
                ('SizeOfHeapCommit', ULONGLONG),
                ('LoaderFlags', DWORD),
                ('NumberOfRvaAndSizes', DWORD),
                ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    ]

IMAGE_OPTIONAL_HEADER64 = _IMAGE_OPTIONAL_HEADER64
PIMAGE_OPTIONAL_HEADER64 = POINTER(IMAGE_OPTIONAL_HEADER64)

IMAGE_SIZEOF_ROM_OPTIONAL_HEADER = 56
IMAGE_SIZEOF_STD_OPTIONAL_HEADER = 28
IMAGE_SIZEOF_NT_OPTIONAL32_HEADER = 224
IMAGE_SIZEOF_NT_OPTIONAL64_HEADER = 240

IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107

# WIN64

IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER64
PIMAGE_OPTIONAL_HEADER = PIMAGE_OPTIONAL_HEADER64
IMAGE_SIZEOF_NT_OPTIONAL_HEADER = IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
IMAGE_NT_OPTIONAL_HDR_MAGIC = IMAGE_NT_OPTIONAL_HDR64_MAGIC

class _IMAGE_NT_HEADERS64(Structure):
    _fields_ = [('Signature', DWORD),
                ('FileHeader', IMAGE_FILE_HEADER),
                ('OptionalHeader', IMAGE_OPTIONAL_HEADER64)
    ]

IMAGE_NT_HEADERS64 = _IMAGE_NT_HEADERS64
PIMAGE_NT_HEADERS64 = POINTER(IMAGE_NT_HEADERS64)

class _IMAGE_NT_HEADERS(Structure):
    _fields_ = [('Signature', DWORD),
                ('FileHeader', IMAGE_FILE_HEADER),
                ('OptionalHeader', IMAGE_OPTIONAL_HEADER32)
    ]

IMAGE_NT_HEADERS32 = _IMAGE_NT_HEADERS
PIMAGE_NT_HEADERS32 = POINTER(IMAGE_NT_HEADERS32)

class _IMAGE_ROM_HEADERS(Structure):
    _fields_ = [('Signature', DWORD),
                ('FileHeader', IMAGE_FILE_HEADER)
    ]

IMAGE_ROM_HEADERS = _IMAGE_ROM_HEADERS
PIMAGE_ROM_HEADERS = POINTER(IMAGE_ROM_HEADERS)

# win64

IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64
PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS64


IMAGE_SUBSYSTEM_UNKNOWN = 0
IMAGE_SUBSYSTEM_NATIVE = 1
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
IMAGE_SUBSYSTEM_OS2_CUI = 5
IMAGE_SUBSYSTEM_POSIX_CUI = 7
IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9
IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
IMAGE_SUBSYSTEM_EFI_ROM = 13
IMAGE_SUBSYSTEM_XBOX = 14
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16

IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

CLSID = GUID

class ANON_OBJECT_HEADER(Structure):
    _fields_ = [('Sig1', WORD),
                ('Sig2', WORD),
                ('Version', WORD),
                ('Machine', WORD),
                ('TimeDateStamp', DWORD),
                ('c', CLSID),
                ('SizeOfData', DWORD)
    ]

class ANON_OBJECT_HEADER_V2(Structure):
    _fields_ = [('Sig1', WORD),
                ('Sig2', WORD),
                ('Version', WORD),
                ('Machine', WORD),
                ('TimeDateStamp', DWORD),
                ('ClassID', CLSID),
                ('SizeOfData', DWORD),
                ('Flags', DWORD),
                ('MetaDataSize', DWORD),
                ('MetaDataOffset', DWORD)
    ]

class ANON_OBJECT_HEADER_BIGOBJ(Structure):
    _fields_ = [('Sig1', WORD),
                ('Sig2', WORD),
                ('Version', WORD),
                ('Machine', WORD),
                ('TimeDateStamp', DWORD),
                ('ClassID', CLSID),
                ('SizeOfData', DWORD),
                ('Flags', DWORD),
                ('MetaDataSize', DWORD),
                ('MetaDataOffset', DWORD),
                ('NumberOfSections', DWORD),
                ('PointerToSymbolTable', DWORD),
                ('NumberOfSymbols', DWORD)
    ]

IMAGE_SIZEOF_SHORT_NAME = 8

class _IMAGE_SECTION_HEADER(Structure):
    class Misc(Union):
        _fields_ = [('PhysicalAddress', DWORD),
                    ('VirtualSize', DWORD)
        ]
    
    _anonymous_ = ['Misc']
    _fields_ = [('Name', BYTE),
                ('Misc', Misc),
                ('VirtualAddress', DWORD),
                ('SizeOfRawData', DWORD),
                ('PointerToRawData', DWORD),
                ('PointerToRelocations', DWORD),
                ('PointerToLinenumbers', DWORD),
                ('NumberOfRelocations', WORD),
                ('NumberOfLinenumbers', WORD),
                ('Characteristics', DWORD)
    ]

IMAGE_SECTION_HEADER = _IMAGE_SECTION_HEADER
PIMAGE_SECTION_HEADER = POINTER(IMAGE_SECTION_HEADER)

IMAGE_SIZEOF_SECTION_HEADER = 40

IMAGE_SCN_TYPE_NO_PAD = 0x00000008

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_LNK_OTHER = 0x00000100
IMAGE_SCN_LNK_INFO = 0x00000200
IMAGE_SCN_LNK_REMOVE = 0x00000800
IMAGE_SCN_LNK_COMDAT = 0x00001000
IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000
IMAGE_SCN_GPREL = 0x00008000
IMAGE_SCN_MEM_FARDATA = 0x00008000
IMAGE_SCN_MEM_PURGEABLE = 0x00020000
IMAGE_SCN_MEM_16BIT = 0x00020000
IMAGE_SCN_MEM_LOCKED = 0x00040000
IMAGE_SCN_MEM_PRELOAD = 0x00080000

IMAGE_SCN_ALIGN_1BYTES = 0x00100000
IMAGE_SCN_ALIGN_2BYTES = 0x00200000
IMAGE_SCN_ALIGN_4BYTES = 0x00300000
IMAGE_SCN_ALIGN_8BYTES = 0x00400000
IMAGE_SCN_ALIGN_16BYTES = 0x00500000
IMAGE_SCN_ALIGN_32BYTES = 0x00600000
IMAGE_SCN_ALIGN_64BYTES = 0x00700000
IMAGE_SCN_ALIGN_128BYTES = 0x00800000
IMAGE_SCN_ALIGN_256BYTES = 0x00900000
IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000

IMAGE_SCN_ALIGN_MASK = 0x00F00000

IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_SCN_SCALE_INDEX = 0x00000001

class _IMAGE_SYMBOL(Structure):
    class N(Union):
        class Name(Structure):
            _fields_ = [('Short', DWORD),
                        ('Long', DWORD)
            ]
        
        _anonymous_ = ['Name']
        _fields_ = [('ShortName', BYTE * 8),
                    ('Name', Name),
                    ('LongName', DWORD * 2),
        ]
    
    _anonymous_ = ['N']
    _fields_ = [('N', N),
                ('Value', DWORD),
                ('SectionNumber', SHORT),
                ('Type', WORD),
                ('StorageClass', BYTE),
                ('NumberOfAuxSymbols', BYTE)
    ]

IMAGE_SYMBOL = _IMAGE_SYMBOL
PIMAGE_SYMBOL = POINTER(IMAGE_SYMBOL)

IMAGE_SIZEOF_SYMBOL = 18

IMAGE_SYMBOL_EX = IMAGE_SYMBOL
PIMAGE_SYMBOL_EX = PIMAGE_SYMBOL

IMAGE_SYM_UNDEFINED = SHORT(0).value
IMAGE_SYM_ABSOLUTE = SHORT(-1).value
IMAGE_SYM_DEBUG = SHORT(-2).value

IMAGE_SYM_SECTION_MAX = 0xFEFF
IMAGE_SYM_SECTION_MAX_EX = MAXLONG

IMAGE_SYM_TYPE_NULL = 0x0000
IMAGE_SYM_TYPE_VOID = 0x0001
IMAGE_SYM_TYPE_CHAR = 0x0002
IMAGE_SYM_TYPE_SHORT = 0x0003
IMAGE_SYM_TYPE_INT = 0x0004
IMAGE_SYM_TYPE_LONG = 0x0005
IMAGE_SYM_TYPE_FLOAT = 0x0006
IMAGE_SYM_TYPE_DOUBLE = 0x0007
IMAGE_SYM_TYPE_STRUCT = 0x0008
IMAGE_SYM_TYPE_UNION = 0x0009
IMAGE_SYM_TYPE_ENUM = 0x000A
IMAGE_SYM_TYPE_MOE = 0x000B
IMAGE_SYM_TYPE_BYTE = 0x000C
IMAGE_SYM_TYPE_WORD = 0x000D
IMAGE_SYM_TYPE_UINT = 0x000E
IMAGE_SYM_TYPE_DWORD = 0x000F
IMAGE_SYM_TYPE_PCODE = 0x8000

IMAGE_SYM_DTYPE_NULL = 0
IMAGE_SYM_DTYPE_POINTER = 1
IMAGE_SYM_DTYPE_FUNCTION = 2
IMAGE_SYM_DTYPE_ARRAY = 3

IMAGE_SYM_CLASS_END_OF_FUNCTION = BYTE(-1).value
IMAGE_SYM_CLASS_NULL = 0x0000
IMAGE_SYM_CLASS_AUTOMATIC = 0x0001
IMAGE_SYM_CLASS_EXTERNAL = 0x0002
IMAGE_SYM_CLASS_STATIC = 0x0003
IMAGE_SYM_CLASS_REGISTER = 0x0004
IMAGE_SYM_CLASS_EXTERNAL_DEF = 0x0005
IMAGE_SYM_CLASS_LABEL = 0x0006
IMAGE_SYM_CLASS_UNDEFINED_LABEL = 0x0007
IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 0x0008
IMAGE_SYM_CLASS_ARGUMENT = 0x0009
IMAGE_SYM_CLASS_STRUCT_TAG = 0x000A
IMAGE_SYM_CLASS_MEMBER_OF_UNION = 0x000B
IMAGE_SYM_CLASS_UNION_TAG = 0x000C
IMAGE_SYM_CLASS_TYPE_DEFINITION = 0x000D
IMAGE_SYM_CLASS_UNDEFINED_STATIC = 0x000E
IMAGE_SYM_CLASS_ENUM_TAG = 0x000F
IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 0x0010
IMAGE_SYM_CLASS_REGISTER_PARAM = 0x0011
IMAGE_SYM_CLASS_BIT_FIELD = 0x0012
IMAGE_SYM_CLASS_FAR_EXTERNAL = 0x0044
IMAGE_SYM_CLASS_BLOCK = 0x0064
IMAGE_SYM_CLASS_FUNCTION = 0x0065
IMAGE_SYM_CLASS_END_OF_STRUCT = 0x0066
IMAGE_SYM_CLASS_FILE = 0x0067
IMAGE_SYM_CLASS_SECTION = 0x0068
IMAGE_SYM_CLASS_WEAK_EXTERNAL = 0x0069
IMAGE_SYM_CLASS_CLR_TOKEN = 0x006B

N_BTMASK = 0x000F
N_TMASK = 0x0030
N_TMASK1 = 0x00C0
N_TMASK2 = 0x00F0
N_BTSHFT = 4
N_TSHIFT = 2


def BTYPE(x: int) -> int:
    return x & N_BTMASK


def ISPTR(x: int) -> bool:
    return (x & N_TMASK)==(IMAGE_SYM_DTYPE_POINTER << N_BTSHFT)


def ISFCN(x: int) -> bool:
    return (x & N_TMASK)==(IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT)


def ISARY(x: int) -> bool:
    return (x & N_TMASK)==(IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT)


def ISTAG(x: int) -> bool:
    return ((x==IMAGE_SYM_CLASS_STRUCT_TAG) or 
            (x==IMAGE_SYM_CLASS_UNION_TAG) or 
            (x==IMAGE_SYM_CLASS_ENUM_TAG)
    )


def INCREF(x: int) -> int:
    return (((x &~ N_BTMASK) << N_TSHIFT) |
            (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT) |
            (x & N_BTMASK)
    )


def DECREF(x: int) -> int:
    return (((x >> N_TSHIFT) &~ N_BTMASK) | 
            (x & N_BTMASK)
    )

class IMAGE_AUX_SYMBOL_TOKEN_DEF(Structure):
    _fields_ = [('bAuxType', BYTE),
                ('bReserved', BYTE),
                ('SymbolTableIndex', DWORD),
                ('rgbReserved', BYTE * 12)
    ]

PIMAGE_AUX_SYMBOL_TOKEN_DEF = POINTER(IMAGE_AUX_SYMBOL_TOKEN_DEF)

class _IMAGE_AUX_SYMBOL(Union):
    class Sym(Structure):
        class Misc(Union):
            class LnSz(Structure):
                _fields_ = [('Linenumber', WORD),
                            ('Size', WORD)
                ]
            
            _anonymous_ = ['LnSz']
            _fields_ = [('LnSz', LnSz),
                        ('TotalSize', DWORD)
            ]
        
        class FcnAry(Union):
            class Function(Structure):
                _fields_ = [('PointerToLinenumber', DWORD),
                            ('PointerToNextFunction', DWORD)
                ]
            
            class Array(Structure):
                _fields_ = [('Dimension', WORD * 4)]
            
            _anonymous_ = ['Function', 'Array']
            _fields_=  [('Function', Function),
                        ('Array', Array)
            ]
        
        _anonymous_ = ['Misc', 'FcnAry']
        _fields_ = [('TagIndex', DWORD),
                    ('Misc', Misc),
                    ('FcnAry', FcnAry),
                    ('TvIndex', WORD),
        ]
    
    class File(Structure):
        _fields_ = [('Name', BYTE * IMAGE_SIZEOF_SYMBOL)]
    
    class Section(Structure):
        _fields_ = [('Length', DWORD),
                    ('NumberOfRelocations', WORD),
                    ('NumberOfLinenumbers', WORD),
                    ('CheckSum', DWORD),
                    ('Number', SHORT),
                    ('Selection', BYTE)
        ]
    
    class CRC(Structure):
        _fields_ = [('crc', DWORD),
                    ('rgbReserved', BYTE * 14)
        ]
    
    _anonymous_ = [
        'Sym',
        'File',
        'Section',
        'CRC'
    ]

    _fields_ = [('Sym', Sym),
                ('File', File),
                ('Section', Section),
                ('CRC', CRC)
    ]

IMAGE_AUX_SYMBOL = _IMAGE_AUX_SYMBOL
PIMAGE_AUX_SYMBOL = POINTER(IMAGE_AUX_SYMBOL)

class _IMAGE_AUX_SYMBOL_EX(Union):
    class Sym(Structure):
        _fields_ = [('WeakDefaultSymIndex', DWORD),
                    ('WeakSearchType', DWORD),
                    ('rgbReserved', BYTE * 12)
        ]
    
    class File(Structure):
        _fields_ = [('Name', BYTE * sizeof(IMAGE_SYMBOL_EX))]
    
    class Section(Structure):
        _fields_ = [('Length', DWORD),
                    ('NumberOfRelocations', WORD),
                    ('NumberOfLinenumbers', WORD),
                    ('CheckSum', DWORD),
                    ('Number', SHORT),
                    ('Selection', BYTE),
                    ('bReserved', BYTE),
                    ('HighNumber', SHORT),
                    ('rgbReserved', BYTE)
        ]
    
    class Tokenrgb(Structure):
        _fields_ = [('TokenDef', IMAGE_AUX_SYMBOL_TOKEN_DEF),
                    ('rgbReserved', BYTE)
        ]
    
    class CRC(Structure):
        _fields_ = [('crc', DWORD),
                    ('rgbReserved', BYTE * 16)
        ]
    
    _anonymous_ = [
        'Sym',
        'File',
        'Section',
        'Tokenrgb',
        'CRC'
    ]

    _fields_ = [('Sym', Sym),
                ('File', File),
                ('Section', Section),
                ('Tokenrgb', Tokenrgb),
                ('CRC', CRC)
    ]

IMAGE_AUX_SYMBOL_EX = _IMAGE_AUX_SYMBOL_EX
PIMAGE_AUX_SYMBOL_EX = POINTER(IMAGE_AUX_SYMBOL_EX)

IMAGE_SIZEOF_AUX_SYMBOL = 18

IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1

class IMAGE_AUX_SYMBOL_TYPE(enum.IntFlag):
    IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1

IMAGE_COMDAT_SELECT_NODUPLICATES = 1
IMAGE_COMDAT_SELECT_ANY = 2
IMAGE_COMDAT_SELECT_SAME_SIZE = 3
IMAGE_COMDAT_SELECT_EXACT_MATCH = 4
IMAGE_COMDAT_SELECT_ASSOCIATIVE = 5
IMAGE_COMDAT_SELECT_LARGEST = 6
IMAGE_COMDAT_SELECT_NEWEST = 7

IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY = 1
IMAGE_WEAK_EXTERN_SEARCH_LIBRARY = 2
IMAGE_WEAK_EXTERN_SEARCH_ALIAS = 3

class _IMAGE_RELOCATION(Structure):
    class VirRelUnion(Union):
        _fields_ = [('VirtualAddress', DWORD),
                    ('RelocCount', DWORD)
        ]
    
    _anonymous_ = ['VirRelUnion']
    _fields_ = [('VirRelUnion', VirRelUnion),
                ('SymbolTableIndex', DWORD),
                ('Type', WORD),
    ]

IMAGE_RELOCATION = _IMAGE_RELOCATION
PIMAGE_RELOCATION = POINTER(IMAGE_RELOCATION)

IMAGE_SIZEOF_RELOCATION = 10

IMAGE_REL_I386_ABSOLUTE = 0x0000
IMAGE_REL_I386_DIR16 = 0x0001
IMAGE_REL_I386_REL16 = 0x0002
IMAGE_REL_I386_DIR32 = 0x0006
IMAGE_REL_I386_DIR32NB = 0x0007
IMAGE_REL_I386_SEG12 = 0x0009
IMAGE_REL_I386_SECTION = 0x000A
IMAGE_REL_I386_SECREL = 0x000B
IMAGE_REL_I386_TOKEN = 0x000C
IMAGE_REL_I386_SECREL7 = 0x000D
IMAGE_REL_I386_REL32 = 0x0014

IMAGE_REL_MIPS_ABSOLUTE = 0x0000
IMAGE_REL_MIPS_REFHALF = 0x0001
IMAGE_REL_MIPS_REFWORD = 0x0002
IMAGE_REL_MIPS_JMPADDR = 0x0003
IMAGE_REL_MIPS_REFHI = 0x0004
IMAGE_REL_MIPS_REFLO = 0x0005
IMAGE_REL_MIPS_GPREL = 0x0006
IMAGE_REL_MIPS_LITERAL = 0x0007
IMAGE_REL_MIPS_SECTION = 0x000A
IMAGE_REL_MIPS_SECREL = 0x000B
IMAGE_REL_MIPS_SECRELLO = 0x000C
IMAGE_REL_MIPS_SECRELHI = 0x000D
IMAGE_REL_MIPS_TOKEN = 0x000E
IMAGE_REL_MIPS_JMPADDR16 = 0x0010
IMAGE_REL_MIPS_REFWORDNB = 0x0022
IMAGE_REL_MIPS_PAIR = 0x0025

IMAGE_REL_ALPHA_ABSOLUTE = 0x0000
IMAGE_REL_ALPHA_REFLONG = 0x0001
IMAGE_REL_ALPHA_REFQUAD = 0x0002
IMAGE_REL_ALPHA_GPREL32 = 0x0003
IMAGE_REL_ALPHA_LITERAL = 0x0004
IMAGE_REL_ALPHA_LITUSE = 0x0005
IMAGE_REL_ALPHA_GPDISP = 0x0006
IMAGE_REL_ALPHA_BRADDR = 0x0007
IMAGE_REL_ALPHA_HINT = 0x0008
IMAGE_REL_ALPHA_INLINE_REFLONG = 0x0009
IMAGE_REL_ALPHA_REFHI = 0x000A
IMAGE_REL_ALPHA_REFLO = 0x000B
IMAGE_REL_ALPHA_PAIR = 0x000C
IMAGE_REL_ALPHA_MATCH = 0x000D
IMAGE_REL_ALPHA_SECTION = 0x000E
IMAGE_REL_ALPHA_SECREL = 0x000F
IMAGE_REL_ALPHA_REFLONGNB = 0x0010
IMAGE_REL_ALPHA_SECRELLO = 0x0011
IMAGE_REL_ALPHA_SECRELHI = 0x0012
IMAGE_REL_ALPHA_REFQ3 = 0x0013
IMAGE_REL_ALPHA_REFQ2 = 0x0014
IMAGE_REL_ALPHA_REFQ1 = 0x0015
IMAGE_REL_ALPHA_GPRELLO = 0x0016
IMAGE_REL_ALPHA_GPRELHI = 0x0017

IMAGE_REL_PPC_ABSOLUTE = 0x0000
IMAGE_REL_PPC_ADDR64 = 0x0001
IMAGE_REL_PPC_ADDR32 = 0x0002
IMAGE_REL_PPC_ADDR24 = 0x0003
IMAGE_REL_PPC_ADDR16 = 0x0004
IMAGE_REL_PPC_ADDR14 = 0x0005
IMAGE_REL_PPC_REL24 = 0x0006
IMAGE_REL_PPC_REL14 = 0x0007
IMAGE_REL_PPC_TOCREL16 = 0x0008
IMAGE_REL_PPC_TOCREL14 = 0x0009
IMAGE_REL_PPC_ADDR32NB = 0x000A
IMAGE_REL_PPC_SECREL = 0x000B
IMAGE_REL_PPC_SECTION = 0x000C
IMAGE_REL_PPC_IFGLUE = 0x000D
IMAGE_REL_PPC_IMGLUE = 0x000E
IMAGE_REL_PPC_SECREL16 = 0x000F
IMAGE_REL_PPC_REFHI = 0x0010
IMAGE_REL_PPC_REFLO = 0x0011
IMAGE_REL_PPC_PAIR = 0x0012
IMAGE_REL_PPC_SECRELLO = 0x0013
IMAGE_REL_PPC_SECRELHI = 0x0014
IMAGE_REL_PPC_GPREL = 0x0015
IMAGE_REL_PPC_TOKEN = 0x0016
IMAGE_REL_PPC_TYPEMASK = 0x00FF
IMAGE_REL_PPC_NEG = 0x0100
IMAGE_REL_PPC_BRTAKEN = 0x0200
IMAGE_REL_PPC_BRNTAKEN = 0x0400
IMAGE_REL_PPC_TOCDEFN = 0x0800

IMAGE_REL_SH3_ABSOLUTE = 0x0000
IMAGE_REL_SH3_DIRECT16 = 0x0001
IMAGE_REL_SH3_DIRECT32 = 0x0002
IMAGE_REL_SH3_DIRECT8 = 0x0003
IMAGE_REL_SH3_DIRECT8_WORD = 0x0004
IMAGE_REL_SH3_DIRECT8_LONG = 0x0005
IMAGE_REL_SH3_DIRECT4 = 0x0006
IMAGE_REL_SH3_DIRECT4_WORD = 0x0007
IMAGE_REL_SH3_DIRECT4_LONG = 0x0008
IMAGE_REL_SH3_PCREL8_WORD = 0x0009
IMAGE_REL_SH3_PCREL8_LONG = 0x000A
IMAGE_REL_SH3_PCREL12_WORD = 0x000B
IMAGE_REL_SH3_STARTOF_SECTION = 0x000C
IMAGE_REL_SH3_SIZEOF_SECTION = 0x000D
IMAGE_REL_SH3_SECTION = 0x000E
IMAGE_REL_SH3_SECREL = 0x000F
IMAGE_REL_SH3_DIRECT32_NB = 0x0010
IMAGE_REL_SH3_GPREL4_LONG = 0x0011
IMAGE_REL_SH3_TOKEN = 0x0012

IMAGE_REL_SHM_PCRELPT = 0x0013
IMAGE_REL_SHM_REFLO = 0x0014
IMAGE_REL_SHM_REFHALF = 0x0015
IMAGE_REL_SHM_RELLO = 0x0016
IMAGE_REL_SHM_RELHALF = 0x0017
IMAGE_REL_SHM_PAIR = 0x0018

IMAGE_REL_SH_NOMODE = 0x8000

IMAGE_REL_ARM_ABSOLUTE = 0x0000
IMAGE_REL_ARM_ADDR32 = 0x0001
IMAGE_REL_ARM_ADDR32NB = 0x0002
IMAGE_REL_ARM_BRANCH24 = 0x0003
IMAGE_REL_ARM_BRANCH11 = 0x0004
IMAGE_REL_ARM_TOKEN = 0x0005
IMAGE_REL_ARM_GPREL12 = 0x0006
IMAGE_REL_ARM_GPREL7 = 0x0007
IMAGE_REL_ARM_BLX24 = 0x0008
IMAGE_REL_ARM_BLX11 = 0x0009
IMAGE_REL_ARM_SECTION = 0x000E
IMAGE_REL_ARM_SECREL = 0x000F
IMAGE_REL_ARM_MOV32A = 0x0010
IMAGE_REL_ARM_MOV32 = 0x0010
IMAGE_REL_ARM_MOV32T = 0x0011
IMAGE_REL_THUMB_MOV32 = 0x0011
IMAGE_REL_ARM_BRANCH20T = 0x0012
IMAGE_REL_THUMB_BRANCH20 = 0x0012
IMAGE_REL_ARM_BRANCH24T = 0x0014
IMAGE_REL_THUMB_BRANCH24 = 0x0014
IMAGE_REL_ARM_BLX23T = 0x0015
IMAGE_REL_THUMB_BLX23 = 0x0015

IMAGE_REL_AM_ABSOLUTE = 0x0000
IMAGE_REL_AM_ADDR32 = 0x0001
IMAGE_REL_AM_ADDR32NB = 0x0002
IMAGE_REL_AM_CALL32 = 0x0003
IMAGE_REL_AM_FUNCINFO = 0x0004
IMAGE_REL_AM_REL32_1 = 0x0005
IMAGE_REL_AM_REL32_2 = 0x0006
IMAGE_REL_AM_SECREL = 0x0007
IMAGE_REL_AM_SECTION = 0x0008
IMAGE_REL_AM_TOKEN = 0x0009

IMAGE_REL_AMD64_ABSOLUTE = 0x0000
IMAGE_REL_AMD64_ADDR64 = 0x0001
IMAGE_REL_AMD64_ADDR32 = 0x0002
IMAGE_REL_AMD64_ADDR32NB = 0x0003
IMAGE_REL_AMD64_REL32 = 0x0004
IMAGE_REL_AMD64_REL32_1 = 0x0005
IMAGE_REL_AMD64_REL32_2 = 0x0006
IMAGE_REL_AMD64_REL32_3 = 0x0007
IMAGE_REL_AMD64_REL32_4 = 0x0008
IMAGE_REL_AMD64_REL32_5 = 0x0009
IMAGE_REL_AMD64_SECTION = 0x000A
IMAGE_REL_AMD64_SECREL = 0x000B
IMAGE_REL_AMD64_SECREL7 = 0x000C
IMAGE_REL_AMD64_TOKEN = 0x000D
IMAGE_REL_AMD64_SREL32 = 0x000E
IMAGE_REL_AMD64_PAIR = 0x000F
IMAGE_REL_AMD64_SSPAN32 = 0x0010

IMAGE_REL_IA64_ABSOLUTE = 0x0000
IMAGE_REL_IA64_IMM14 = 0x0001
IMAGE_REL_IA64_IMM22 = 0x0002
IMAGE_REL_IA64_IMM64 = 0x0003
IMAGE_REL_IA64_DIR32 = 0x0004
IMAGE_REL_IA64_DIR64 = 0x0005
IMAGE_REL_IA64_PCREL21B = 0x0006
IMAGE_REL_IA64_PCREL21M = 0x0007
IMAGE_REL_IA64_PCREL21F = 0x0008
IMAGE_REL_IA64_GPREL22 = 0x0009
IMAGE_REL_IA64_LTOFF22 = 0x000A
IMAGE_REL_IA64_SECTION = 0x000B
IMAGE_REL_IA64_SECREL22 = 0x000C
IMAGE_REL_IA64_SECREL64I = 0x000D
IMAGE_REL_IA64_SECREL32 = 0x000E

IMAGE_REL_IA64_DIR32NB = 0x0010
IMAGE_REL_IA64_SREL14 = 0x0011
IMAGE_REL_IA64_SREL22 = 0x0012
IMAGE_REL_IA64_SREL32 = 0x0013
IMAGE_REL_IA64_UREL32 = 0x0014
IMAGE_REL_IA64_PCREL60X = 0x0015
IMAGE_REL_IA64_PCREL60B = 0x0016
IMAGE_REL_IA64_PCREL60F = 0x0017
IMAGE_REL_IA64_PCREL60I = 0x0018
IMAGE_REL_IA64_PCREL60M = 0x0019
IMAGE_REL_IA64_IMMGPREL64 = 0x001A
IMAGE_REL_IA64_TOKEN = 0x001B
IMAGE_REL_IA64_GPREL32 = 0x001C
IMAGE_REL_IA64_ADDEND = 0x001F

IMAGE_REL_CEF_ABSOLUTE = 0x0000
IMAGE_REL_CEF_ADDR32 = 0x0001
IMAGE_REL_CEF_ADDR64 = 0x0002
IMAGE_REL_CEF_ADDR32NB = 0x0003
IMAGE_REL_CEF_SECTION = 0x0004
IMAGE_REL_CEF_SECREL = 0x0005
IMAGE_REL_CEF_TOKEN = 0x0006

IMAGE_REL_CEE_ABSOLUTE = 0x0000
IMAGE_REL_CEE_ADDR32 = 0x0001
IMAGE_REL_CEE_ADDR64 = 0x0002
IMAGE_REL_CEE_ADDR32NB = 0x0003
IMAGE_REL_CEE_SECTION = 0x0004
IMAGE_REL_CEE_SECREL = 0x0005
IMAGE_REL_CEE_TOKEN = 0x0006

IMAGE_REL_M32R_ABSOLUTE = 0x0000
IMAGE_REL_M32R_ADDR32 = 0x0001
IMAGE_REL_M32R_ADDR32NB = 0x0002
IMAGE_REL_M32R_ADDR24 = 0x0003
IMAGE_REL_M32R_GPREL16 = 0x0004
IMAGE_REL_M32R_PCREL24 = 0x0005
IMAGE_REL_M32R_PCREL16 = 0x0006
IMAGE_REL_M32R_PCREL8 = 0x0007
IMAGE_REL_M32R_REFHALF = 0x0008
IMAGE_REL_M32R_REFHI = 0x0009
IMAGE_REL_M32R_REFLO = 0x000A
IMAGE_REL_M32R_PAIR = 0x000B
IMAGE_REL_M32R_SECTION = 0x000C
IMAGE_REL_M32R_SECREL32 = 0x000D
IMAGE_REL_M32R_TOKEN = 0x000E

IMAGE_REL_EBC_ABSOLUTE = 0x0000
IMAGE_REL_EBC_ADDR32NB = 0x0001
IMAGE_REL_EBC_REL32 = 0x0002
IMAGE_REL_EBC_SECTION = 0x0003
IMAGE_REL_EBC_SECREL = 0x0004

EMARCH_ENC_I17_IMM7B_INST_WORD_X = 3
EMARCH_ENC_I17_IMM7B_SIZE_X = 7
EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X = 4
EMARCH_ENC_I17_IMM7B_VAL_POS_X = 0

EMARCH_ENC_I17_IMM9D_INST_WORD_X = 3
EMARCH_ENC_I17_IMM9D_SIZE_X = 9
EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X = 18
EMARCH_ENC_I17_IMM9D_VAL_POS_X = 7

EMARCH_ENC_I17_IMM5C_INST_WORD_X = 3
EMARCH_ENC_I17_IMM5C_SIZE_X = 5
EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X = 13
EMARCH_ENC_I17_IMM5C_VAL_POS_X = 16

EMARCH_ENC_I17_IC_INST_WORD_X = 3
EMARCH_ENC_I17_IC_SIZE_X = 1
EMARCH_ENC_I17_IC_INST_WORD_POS_X = 12
EMARCH_ENC_I17_IC_VAL_POS_X = 21

EMARCH_ENC_I17_IMM41a_INST_WORD_X = 1
EMARCH_ENC_I17_IMM41a_SIZE_X = 10
EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X = 14
EMARCH_ENC_I17_IMM41a_VAL_POS_X = 22

EMARCH_ENC_I17_IMM41b_INST_WORD_X = 1
EMARCH_ENC_I17_IMM41b_SIZE_X = 8
EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X = 24
EMARCH_ENC_I17_IMM41b_VAL_POS_X = 32

EMARCH_ENC_I17_IMM41c_INST_WORD_X = 2
EMARCH_ENC_I17_IMM41c_SIZE_X = 23
EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X = 0
EMARCH_ENC_I17_IMM41c_VAL_POS_X = 40

EMARCH_ENC_I17_SIGN_INST_WORD_X = 3
EMARCH_ENC_I17_SIGN_SIZE_X = 1
EMARCH_ENC_I17_SIGN_INST_WORD_POS_X = 27
EMARCH_ENC_I17_SIGN_VAL_POS_X = 63

X3_OPCODE_INST_WORD_X = 3
X3_OPCODE_SIZE_X = 4
X3_OPCODE_INST_WORD_POS_X = 28
X3_OPCODE_SIGN_VAL_POS_X = 0

X3_I_INST_WORD_X = 3
X3_I_SIZE_X = 1
X3_I_INST_WORD_POS_X = 27
X3_I_SIGN_VAL_POS_X = 59

X3_D_WH_INST_WORD_X = 3
X3_D_WH_SIZE_X = 3
X3_D_WH_INST_WORD_POS_X = 24
X3_D_WH_SIGN_VAL_POS_X = 0

X3_IMM20_INST_WORD_X = 3
X3_IMM20_SIZE_X = 20
X3_IMM20_INST_WORD_POS_X = 4
X3_IMM20_SIGN_VAL_POS_X = 0

X3_IMM39_1_INST_WORD_X = 2
X3_IMM39_1_SIZE_X = 23
X3_IMM39_1_INST_WORD_POS_X = 0
X3_IMM39_1_SIGN_VAL_POS_X = 36

X3_IMM39_2_INST_WORD_X = 1
X3_IMM39_2_SIZE_X = 16
X3_IMM39_2_INST_WORD_POS_X = 16
X3_IMM39_2_SIGN_VAL_POS_X = 20

X3_P_INST_WORD_X = 3
X3_P_SIZE_X = 4
X3_P_INST_WORD_POS_X = 0
X3_P_SIGN_VAL_POS_X = 0

X3_TMPLT_INST_WORD_X = 0
X3_TMPLT_SIZE_X = 4
X3_TMPLT_INST_WORD_POS_X = 0
X3_TMPLT_SIGN_VAL_POS_X = 0

X3_BTYPE_QP_INST_WORD_X = 2
X3_BTYPE_QP_SIZE_X = 9
X3_BTYPE_QP_INST_WORD_POS_X = 23
X3_BTYPE_QP_INST_VAL_POS_X = 0

X3_EMPTY_INST_WORD_X = 1
X3_EMPTY_SIZE_X = 2
X3_EMPTY_INST_WORD_POS_X = 14
X3_EMPTY_INST_VAL_POS_X = 0

class _IMAGE_LINENUMBER(Structure):
    class Type(Union):
        _fields_ = [('SymbolTableIndex', DWORD),
                    ('VirtualAddress', DWORD)
        ]
    
    _anonymous_ = ['Type']
    _fields_ = [('Type', Type),
                ('Linenumber', WORD)
    ]

IMAGE_LINENUMBER = _IMAGE_LINENUMBER
PIMAGE_LINENUMBER = POINTER(IMAGE_LINENUMBER)

IMAGE_SIZEOF_LINENUMBER = 6

class _IMAGE_BASE_RELOCATION(Structure):
    _fields_ = [('VirtualAddress', DWORD),
                ('SizeOfBlock', DWORD)
    ]

IMAGE_BASE_RELOCATION = _IMAGE_BASE_RELOCATION
PIMAGE_BASE_RELOCATION = POINTER(IMAGE_BASE_RELOCATION)

IMAGE_SIZEOF_BASE_RELOCATION = 8

IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGH = 1
IMAGE_REL_BASED_LOW = 2
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_HIGHADJ = 4
IMAGE_REL_BASED_MIPS_JMPADDR = 5
IMAGE_REL_BASED_ARM_MOV32 = 5
IMAGE_REL_BASED_THUMB_MOV32 = 7
IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
IMAGE_REL_BASED_IA64_IMM64 = 9
IMAGE_REL_BASED_DIR64 = 10

IMAGE_ARCHIVE_START_SIZE = 8
IMAGE_ARCHIVE_START = "!<arch>\n"
IMAGE_ARCHIVE_END = "`\n"
IMAGE_ARCHIVE_PAD = "\n"
IMAGE_ARCHIVE_LINKER_MEMBER = "/               "
IMAGE_ARCHIVE_LONGNAMES_MEMBER = "//              "

class _IMAGE_ARCHIVE_MEMBER_HEADER(Structure):
    _fields_ = [('Name', BYTE * 16),
                ('Date', BYTE * 12),
                ('UserID', BYTE * 6),
                ('GroupID', BYTE * 6),
                ('Mode', BYTE * 8),
                ('Size', BYTE * 10),
                ('EndHeader', BYTE * 2)
    ]

IMAGE_ARCHIVE_MEMBER_HEADER = _IMAGE_ARCHIVE_MEMBER_HEADER
PIMAGE_ARCHIVE_MEMBER_HEADER = POINTER(IMAGE_ARCHIVE_MEMBER_HEADER)

IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR = 60

class _IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [('Characteristics', DWORD),
                ('TimeDateStamp', DWORD),
                ('MajorVersion', DWORD),
                ('MinorVersion', DWORD),
                ('Name', DWORD),
                ('Base', DWORD),
                ('NumberOfFunctions', DWORD),
                ('NumberOfNames', DWORD),
                ('AddressOfFunctions', DWORD),
                ('AddressOfNames', DWORD),
                ('AddressOfNameOrdinals', DWORD)
    ]

IMAGE_EXPORT_DIRECTORY = _IMAGE_EXPORT_DIRECTORY
PIMAGE_EXPORT_DIRECTORY = POINTER(IMAGE_EXPORT_DIRECTORY)

class  _IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [('Hint', WORD),
                ('Name', CHAR * 1)
    ]

IMAGE_IMPORT_BY_NAME = _IMAGE_IMPORT_BY_NAME
PIMAGE_IMPORT_BY_NAME = POINTER(IMAGE_IMPORT_BY_NAME)

class _IMAGE_THUNK_DATA64(Structure):
    class u1(Union):
        _fields_ = [('ForwarderString', ULONGLONG),
                    ('Function', ULONGLONG),
                    ('Ordinal', ULONGLONG),
                    ('AddressOfData', ULONGLONG)
        ]
    _anonymous_ = ['u1']
    _fields_ = [('u1', u1)]

IMAGE_THUNK_DATA64 = _IMAGE_THUNK_DATA64
PIMAGE_THUNK_DATA64 = POINTER(IMAGE_THUNK_DATA64)

class _IMAGE_THUNK_DATA32(Structure):
    class u1(Union):
        _fields_ = [('ForwarderString', DWORD),
                    ('Function', DWORD),
                    ('Ordinal', DWORD),
                    ('AddressOfData', DWORD)
        ]
    
    _anonymous_ = ['u1']
    _fields_ = [('u1', u1)]

IMAGE_THUNK_DATA32 = _IMAGE_THUNK_DATA32
PIMAGE_THUNK_DATA32 = POINTER(IMAGE_THUNK_DATA32)

IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
IMAGE_ORDINAL_FLAG32 = 0x80000000

def IMAGE_ORDINAL64(Ordinal):
    return Ordinal & 0xffff


def IMAGE_ORDINAL32(Ordinal):
    return Ordinal & 0xffff


def IMAGE_SNAP_BY_ORDINAL64(Ordinal):
     return (Ordinal & IMAGE_ORDINAL_FLAG64) != 0


def IMAGE_SNAP_BY_ORDINAL32(Ordinal):
    return (Ordinal & IMAGE_ORDINAL_FLAG32) != 0


PIMAGE_TLS_CALLBACK = NTAPI(VOID, PVOID, DWORD, PVOID)

class _IMAGE_TLS_DIRECTORY64(Structure):
    _fields_ = [('StartAddressOfRawData', ULONGLONG),
                ('EndAddressOfRawData', ULONGLONG),
                ('AddressOfIndex', ULONGLONG),
                ('AddressOfCallBacks', ULONGLONG),
                ('SizeOfZeroFill', DWORD),
                ('Characteristics', DWORD)
    ]

IMAGE_TLS_DIRECTORY64 = _IMAGE_TLS_DIRECTORY64
PIMAGE_TLS_DIRECTORY64 = POINTER(IMAGE_TLS_DIRECTORY64)

class _IMAGE_TLS_DIRECTORY32(Structure):
    _fields_ = [('StartAddressOfRawData', DWORD),
                ('EndAddressOfRawData', DWORD),
                ('AddressOfIndex', DWORD),
                ('AddressOfCallBacks', DWORD),
                ('SizeOfZeroFill', DWORD),
                ('Characteristics', DWORD)
    ]

IMAGE_TLS_DIRECTORY32 = _IMAGE_TLS_DIRECTORY32
PIMAGE_TLS_DIRECTORY32 = POINTER(IMAGE_TLS_DIRECTORY32)

IMAGE_RESOURCE_NAME_IS_STRING = 0x80000000
IMAGE_RESOURCE_DATA_IS_DIRECTORY = 0x80000000

# win64

IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64


def IMAGE_ORDINAL(Ordinal):
    return IMAGE_ORDINAL64(Ordinal)


IMAGE_THUNK_DATA = IMAGE_THUNK_DATA64
PIMAGE_THUNK_DATA = PIMAGE_THUNK_DATA64


def IMAGE_SNAP_BY_ORDINAL(Ordinal):
    return IMAGE_SNAP_BY_ORDINAL64(Ordinal)


IMAGE_TLS_DIRECTORY = IMAGE_TLS_DIRECTORY64
PIMAGE_TLS_DIRECTORY = PIMAGE_TLS_DIRECTORY64

class _IMAGE_IMPORT_DESCRIPTOR(Structure):
    class DUMMYUNIONNAME(Union):
        _fields_ = [('Characteristics', DWORD),
                    ('OriginalFirstThunk', DWORD)
        ]
    
    _anonymous_ = ['DUMMYUNIONNAME']
    _fields_ = [('DUMMYUNIONNAME', DUMMYUNIONNAME),
                ('TimeDateStamp', DWORD),
                ('ForwarderChain', DWORD),
                ('Name', DWORD),
                ('FirstThunk', DWORD)
    ]

IMAGE_IMPORT_DESCRIPTOR = _IMAGE_IMPORT_DESCRIPTOR
PIMAGE_IMPORT_DESCRIPTOR = POINTER(IMAGE_IMPORT_DESCRIPTOR)

class _IMAGE_BOUND_IMPORT_DESCRIPTOR(Structure):
    _fields_ = [('TimeDateStamp', DWORD),
                ('OffsetModuleName', WORD),
                ('NumberOfModuleForwarderRefs', WORD)
    ]

IMAGE_BOUND_IMPORT_DESCRIPTOR = _IMAGE_BOUND_IMPORT_DESCRIPTOR
PIMAGE_BOUND_IMPORT_DESCRIPTOR = POINTER(IMAGE_BOUND_IMPORT_DESCRIPTOR)

class _IMAGE_BOUND_FORWARDER_REF(Structure):
    _fields_ = [('TimeDateStamp', DWORD),
                ('OffsetModuleName', WORD),
                ('Reserved', WORD)
    ]

IMAGE_BOUND_FORWARDER_REF = _IMAGE_BOUND_FORWARDER_REF
PIMAGE_BOUND_FORWARDER_REF = POINTER(IMAGE_BOUND_FORWARDER_REF)

class _IMAGE_DELAYLOAD_DESCRIPTOR(Structure):
    class Attributes(Union):
        class RvaResLittleStruct(LittleEndianStructure):
            _fields_ = [('RvaBased', DWORD, 1),
                        ('ReservedAttributes', DWORD, 31)
            ]
        
        _anonymous_ = ['RvaResLittleStruct']
        _fields_ = [('AllAttributes', DWORD), 
                    ('RvaResLittleStruct', RvaResLittleStruct)
        ]
    
    _anonymous_ = ['Attributes']
    _fields_ = [('Attributes', Attributes),
                ('DllNameRVA', DWORD),
                ('ModuleHandleRVA', DWORD),
                ('ImportAddressTableRVA', DWORD),
                ('ImportNameTableRVA', DWORD),
                ('BoundImportAddressTableRVA', DWORD),
                ('UnloadInformationTableRVA', DWORD),
                ('TimeDateStamp', DWORD)
    ]

IMAGE_DELAYLOAD_DESCRIPTOR = _IMAGE_DELAYLOAD_DESCRIPTOR
PIMAGE_DELAYLOAD_DESCRIPTOR = POINTER(IMAGE_DELAYLOAD_DESCRIPTOR)

PCIMAGE_DELAYLOAD_DESCRIPTOR = PIMAGE_DELAYLOAD_DESCRIPTOR

class _IMAGE_RESOURCE_DIRECTORY(Structure):
    _fields_ = [('Characteristics', DWORD),
                ('TimeDateStamp', DWORD),
                ('MajorVersion', WORD),
                ('MinorVersion', WORD),
                ('NumberOfNamedEntries', WORD),
                ('NumberOfIdEntries', WORD)
    ]

IMAGE_RESOURCE_DIRECTORY = _IMAGE_RESOURCE_DIRECTORY
PIMAGE_RESOURCE_DIRECTORY = POINTER(IMAGE_RESOURCE_DIRECTORY)

IMAGE_RESOURCE_NAME_IS_STRING = 0x80000000
IMAGE_RESOURCE_DATA_IS_DIRECTORY = 0x80000000

class _IMAGE_RESOURCE_DIRECTORY_ENTRY(Structure):
    class NameIdStructure(Structure):
        class NameLittleStruct(LittleEndianStructure):
            _fields_ = [('NameOffset', DWORD, 31),
                        ('NameIsString', DWORD, 1)
            ]
        
        _anonymous_ = ['NameLittleStruct']
        _fields_ = [('NameLittleStruct', NameLittleStruct),
                    ('Name', DWORD),
                    ('Id', DWORD)
        ]
    
    class OffsetToDataUnion(Union):
        class OffsetDataLittleStruct(LittleEndianStructure):
            _fields_ = [('OffsetToDirectory', DWORD, 31),
                        ('DataIsDirectory', DWORD, 1),
            ]
        
        _anonymous_ = ['OffsetDataLittleStruct']
        _fields_ = [('OffsetToData', DWORD),
                    ('OffsetDataLittleStruct', OffsetDataLittleStruct)
        ]
    
    _anonymous_ = ['NameIdStructure', 'OffsetToDataUnion']
    _fields_ = [('NameIdStructure', NameIdStructure),
                ('OffsetToDataUnion', OffsetToDataUnion)
    ]

IMAGE_RESOURCE_DIRECTORY_ENTRY = _IMAGE_RESOURCE_DIRECTORY_ENTRY
PIMAGE_RESOURCE_DIRECTORY_ENTRY = POINTER(IMAGE_RESOURCE_DIRECTORY_ENTRY)

class _IMAGE_RESOURCE_DIRECTORY_STRING(Structure):
    _fields_ = [('Length', WORD),
                ('NameString', CHAR * 1)
    ]

IMAGE_RESOURCE_DIRECTORY_STRING = _IMAGE_RESOURCE_DIRECTORY_STRING
PIMAGE_RESOURCE_DIRECTORY_STRING = POINTER(IMAGE_RESOURCE_DIRECTORY_STRING)

class _IMAGE_RESOURCE_DIR_STRING_U(Structure):
     _fields_ = [('Length', WORD),
                ('NameString', WCHAR * 1)
    ]
    
IMAGE_RESOURCE_DIR_STRING_U = _IMAGE_RESOURCE_DIR_STRING_U
PIMAGE_RESOURCE_DIR_STRING_U = POINTER(IMAGE_RESOURCE_DIR_STRING_U)

class _IMAGE_RESOURCE_DATA_ENTRY(Structure):
    _fields_ = [('OffsetToData', DWORD),
                ('Size', DWORD),
                ('CodePage', DWORD),
                ('Reserved', DWORD),
    ]

IMAGE_RESOURCE_DATA_ENTRY = _IMAGE_RESOURCE_DATA_ENTRY
PIMAGE_RESOURCE_DATA_ENTRY = POINTER(IMAGE_RESOURCE_DATA_ENTRY)

class IMAGE_LOAD_CONFIG_DIRECTORY32(Structure):
    _fields_ = [('Size', DWORD),
                ('TimeDateStamp', DWORD),
                ('MajorVersion', WORD),
                ('MinorVersion', WORD),
                ('GlobalFlagsClear', DWORD),
                ('GlobalFlagsSet', DWORD),
                ('CriticalSectionDefaultTimeout', DWORD),
                ('DeCommitFreeBlockThreshold', DWORD),
                ('DeCommitTotalFreeThreshold', DWORD),
                ('LockPrefixTable', DWORD),
                ('MaximumAllocationSize', DWORD),
                ('VirtualMemoryThreshold', DWORD),
                ('ProcessHeapFlags', DWORD),
                ('ProcessAffinityMask', DWORD),
                ('CSDVersion', WORD),
                ('Reserved1', WORD),
                ('EditList', DWORD),
                ('SecurityCookie', DWORD),
                ('SEHandlerTable', DWORD),
                ('SEHandlerCount', DWORD)
    ]

PIMAGE_LOAD_CONFIG_DIRECTORY32 = POINTER(IMAGE_LOAD_CONFIG_DIRECTORY32)

class IMAGE_LOAD_CONFIG_DIRECTORY64(Structure):
    _fields_ = [('Size', DWORD),
                ('TimeDateStamp', DWORD),
                ('MajorVersion', WORD),
                ('MinorVersion', WORD),
                ('GlobalFlagsClear', DWORD),
                ('GlobalFlagsSet', DWORD),
                ('CriticalSectionDefaultTimeout', DWORD),
                ('DeCommitFreeBlockThreshold', ULONGLONG),
                ('DeCommitTotalFreeThreshold', ULONGLONG),
                ('LockPrefixTable', ULONGLONG),
                ('MaximumAllocationSize', ULONGLONG),
                ('VirtualMemoryThreshold', ULONGLONG),
                ('ProcessAffinityMask', ULONGLONG),
                ('ProcessHeapFlags', DWORD),
                ('CSDVersion', WORD),
                ('Reserved1', WORD),
                ('EditList', ULONGLONG),
                ('SecurityCookie', ULONGLONG),
                ('SEHandlerTable', ULONGLONG),
                ('SEHandlerCount', ULONGLONG)
    ]

PIMAGE_LOAD_CONFIG_DIRECTORY64 = POINTER(IMAGE_LOAD_CONFIG_DIRECTORY64)

# win64

IMAGE_LOAD_CONFIG_DIRECTORY = IMAGE_LOAD_CONFIG_DIRECTORY64
PIMAGE_LOAD_CONFIG_DIRECTORY = PIMAGE_LOAD_CONFIG_DIRECTORY64

class _IMAGE_CE_RUNTIME_FUNCTION_ENTRY(Structure):
    _fields_ = [('FuncStart', DWORD),
                ('PrologLen', DWORD, 8),
                ('FuncLen', DWORD, 22),
                ('ThirtyTwoBit', DWORD, 1),
                ('ExceptionFlag', DWORD, 1)
    ]

IMAGE_CE_RUNTIME_FUNCTION_ENTRY = _IMAGE_CE_RUNTIME_FUNCTION_ENTRY
PIMAGE_CE_RUNTIME_FUNCTION_ENTRY = POINTER(IMAGE_CE_RUNTIME_FUNCTION_ENTRY)

class _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY(Structure):
    _fields_ = [('BeginAddress', ULONGLONG),
                ('EndAddress', ULONGLONG),
                ('ExceptionHandler', ULONGLONG),
                ('HandlerData', ULONGLONG),
                ('PrologEndAddress', ULONGLONG)
    ]

IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY = _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY
PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY = POINTER(IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY)

class _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY(Structure):
    _fields_ = [('BeginAddress', DWORD),
                ('EndAddress', DWORD),
                ('ExceptionHandler', DWORD),
                ('HandlerData', DWORD),
                ('PrologEndAddress', DWORD)
    ]

IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY = _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY
PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY = POINTER(IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY)

class _IMAGE_RUNTIME_FUNCTION_ENTRY(Structure):
    class UnwinUnion(Union):
        _fields_ = [('UnwindInfoAddress', DWORD),
                    ('UnwindData', DWORD)
        ]
    
    _anonymous_ = ['UnwinUnion']
    _fields_ = [('BeginAddress', DWORD),
                ('EndAddress', DWORD),
                ('UnwinUnion', UnwinUnion)
    ]

_PIMAGE_RUNTIME_FUNCTION_ENTRY = POINTER(_IMAGE_RUNTIME_FUNCTION_ENTRY)
IMAGE_IA64_RUNTIME_FUNCTION_ENTRY = _IMAGE_RUNTIME_FUNCTION_ENTRY
PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY = _PIMAGE_RUNTIME_FUNCTION_ENTRY

IMAGE_RUNTIME_FUNCTION_ENTRY = _IMAGE_RUNTIME_FUNCTION_ENTRY
PIMAGE_RUNTIME_FUNCTION_ENTRY = _PIMAGE_RUNTIME_FUNCTION_ENTRY

class _IMAGE_DEBUG_DIRECTORY(Structure):
    _fields_ = [('Characteristics', DWORD),
                ('TimeDateStamp', DWORD),
                ('MajorVersion', WORD),
                ('MinorVersion', WORD),
                ('Type', DWORD),
                ('SizeOfData', DWORD),
                ('AddressOfRawData', DWORD),
                ('PointerToRawData', DWORD)
    ]

IMAGE_DEBUG_DIRECTORY = _IMAGE_DEBUG_DIRECTORY
PIMAGE_DEBUG_DIRECTORY = POINTER(IMAGE_DEBUG_DIRECTORY)

IMAGE_DEBUG_TYPE_UNKNOWN = 0
IMAGE_DEBUG_TYPE_COFF = 1
IMAGE_DEBUG_TYPE_CODEVIEW = 2
IMAGE_DEBUG_TYPE_FPO = 3
IMAGE_DEBUG_TYPE_MISC = 4
IMAGE_DEBUG_TYPE_EXCEPTION = 5
IMAGE_DEBUG_TYPE_FIXUP = 6
IMAGE_DEBUG_TYPE_OMAP_TO_SRC = 7
IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8
IMAGE_DEBUG_TYPE_BORLAND = 9
IMAGE_DEBUG_TYPE_RESERVED10 = 10
IMAGE_DEBUG_TYPE_CLSID = 11

class _IMAGE_COFF_SYMBOLS_HEADER(Structure):
    _fields_ = [('NumberOfSymbols', DWORD),
                ('LvaToFirstSymbol', DWORD),
                ('NumberOfLinenumbers', DWORD),
                ('LvaToFirstLinenumber', DWORD),
                ('RvaToFirstByteOfCode', DWORD),
                ('RvaToLastByteOfCode', DWORD),
                ('RvaToFirstByteOfData', DWORD),
                ('RvaToLastByteOfData', DWORD)
    ]

IMAGE_COFF_SYMBOLS_HEADER = _IMAGE_COFF_SYMBOLS_HEADER
PIMAGE_COFF_SYMBOLS_HEADER = POINTER(IMAGE_COFF_SYMBOLS_HEADER)

FRAME_FPO = 0
FRAME_TRAP = 1
FRAME_TSS = 2
FRAME_NONFPO = 3

class _FPO_DATA(Structure):
    _fields_ = [('ulOffStart', DWORD),
                ('cbProcSize', DWORD),
                ('cdwLocals', DWORD),
                ('cdwParams', WORD),
                ('cbProlog', WORD, 8),
                ('cbRegs', WORD, 3),
                ('fHasSEH', WORD, 1),
                ('fUseBP', WORD, 1),
                ('reserved', WORD, 1),
                ('cbFrame', WORD, 2)
    ]

FPO_DATA = _FPO_DATA
PFPO_DATA = POINTER(FPO_DATA)

SIZEOF_RFPO_DATA = 16

IMAGE_DEBUG_MISC_EXENAME = 1

class _IMAGE_DEBUG_MISC(Structure):
    _fields_ = [('DataType', DWORD),
                ('Length', DWORD),
                ('Unicode', BOOLEAN),
                ('Reserved', BYTE * 3),
                ('Data', BYTE * 1)
    ]

IMAGE_DEBUG_MISC = _IMAGE_DEBUG_MISC
PIMAGE_DEBUG_MISC = POINTER(IMAGE_DEBUG_MISC)

class _IMAGE_FUNCTION_ENTRY(Structure):
    _fields_ = [('StartingAddress', DWORD),
                ('EndingAddress', DWORD),
                ('EndOfPrologue', DWORD)
    ]

IMAGE_FUNCTION_ENTRY = _IMAGE_FUNCTION_ENTRY
PIMAGE_FUNCTION_ENTRY = POINTER(IMAGE_FUNCTION_ENTRY)

class _IMAGE_FUNCTION_ENTRY64(Structure):
    class EndUnwindUnion(Union):
        _fields_ = [('EndOfPrologue', ULONGLONG),
                    ('UnwindInfoAddress', ULONGLONG)
        ]

    _anonymous_ = ['EndUnwindUnion']
    _fields_ = [('StartingAddress', ULONGLONG),
                ('EndingAddress', ULONGLONG),
                ('EndUnwindUnion', EndUnwindUnion)
    ]

IMAGE_FUNCTION_ENTRY64 = _IMAGE_FUNCTION_ENTRY64
PIMAGE_FUNCTION_ENTRY64 = POINTER(IMAGE_FUNCTION_ENTRY64)

class _IMAGE_SEPARATE_DEBUG_HEADER(Structure):
    _fields_ = [('Signature', WORD),
                ('Flags', WORD),
                ('Machine', WORD),
                ('Characteristics', WORD),
                ('TimeDateStamp', DWORD),
                ('CheckSum', DWORD),
                ('ImageBase', DWORD),
                ('SizeOfImage', DWORD),
                ('NumberOfSections', DWORD),
                ('ExportedNamesSize', DWORD),
                ('DebugDirectorySize', DWORD),
                ('SectionAlignment', DWORD),
                ('Reserved', DWORD * 2)
    ]

IMAGE_SEPARATE_DEBUG_HEADER = _IMAGE_SEPARATE_DEBUG_HEADER
PIMAGE_SEPARATE_DEBUG_HEADER = POINTER(IMAGE_SEPARATE_DEBUG_HEADER)

class _NON_PAGED_DEBUG_INFO(Structure):
    _fields_ = [('Signature', WORD),
                ('Flags', WORD),
                ('Size', DWORD),
                ('Machine', WORD),
                ('Characteristics', WORD),
                ('TimeDateStamp', DWORD),
                ('CheckSum', DWORD),
                ('SizeOfImage', DWORD),
                ('ImageBase', ULONGLONG)
    ]

NON_PAGED_DEBUG_INFO = _NON_PAGED_DEBUG_INFO
PNON_PAGED_DEBUG_INFO = POINTER(NON_PAGED_DEBUG_INFO)

IMAGE_SEPARATE_DEBUG_SIGNATURE = 0x4944
NON_PAGED_DEBUG_SIGNATURE = 0x494E

IMAGE_SEPARATE_DEBUG_FLAGS_MASK = 0x8000
IMAGE_SEPARATE_DEBUG_MISMATCH = 0x8000

class _ImageArchitectureHeader(Structure):
    _fields_ = [('AmaskValue', UINT),
                ('Adummy1', INT),
                ('AmaskShift', UINT),
                ('Adummy2', INT),
                ('FirstEntryRVA', DWORD)
    ]
IMAGE_ARCHITECTURE_HEADER = _ImageArchitectureHeader
PIMAGE_ARCHITECTURE_HEADER = POINTER(IMAGE_ARCHITECTURE_HEADER)

class _ImageArchitectureEntry(Structure):
    _fields_ = [('FixupInstRVA', DWORD),
                ('NewInst', DWORD)
    ]

IMAGE_ARCHITECTURE_ENTRY = _ImageArchitectureEntry
PIMAGE_ARCHITECTURE_ENTRY = POINTER(IMAGE_ARCHITECTURE_ENTRY)

IMPORT_OBJECT_HDR_SIG2 = 0xffff

class IMPORT_OBJECT_HEADER(Structure):
    class OrdHinUnion(Union):
        _fields_ = [('Ordinal', WORD),
                    ('Hint', WORD)
        ]

    _anonymous_ = ['OrdHinUnion']
    _fields_ = [('Sig1', WORD),
                ('Sig2', WORD),
                ('Version', WORD),
                ('Machine', WORD),
                ('TimeDateStamp', DWORD),
                ('SizeOfData', DWORD),
                ('OrdHinUnion', OrdHinUnion),
                ('Type', WORD, 2),
                ('NameType', WORD, 3),
                ('Reserved', WORD, 11)
    ]

IMPORT_OBJECT_CODE = 0
IMPORT_OBJECT_DATA = 1
IMPORT_OBJECT_CONST = 2

class IMPORT_OBJECT_TYPE(enum.IntFlag):
    IMPORT_OBJECT_CODE = 0
    IMPORT_OBJECT_DATA = 1
    IMPORT_OBJECT_CONST = 2

IMPORT_OBJECT_ORDINAL = 0
IMPORT_OBJECT_NAME = 1
IMPORT_OBJECT_NAME_NO_PREFIX = 2
IMPORT_OBJECT_NAME_UNDECORATE = 3

class IMPORT_OBJECT_NAME_TYPE(enum.IntFlag):
    IMPORT_OBJECT_ORDINAL = 0
    IMPORT_OBJECT_NAME = 1
    IMPORT_OBJECT_NAME_NO_PREFIX = 2
    IMPORT_OBJECT_NAME_UNDECORATE = 3

COMIMAGE_FLAGS_ILONLY = 0x00000001
COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004
COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008
COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x00010000
COR_VERSION_MAJOR_V2 = 2
COR_VERSION_MAJOR = COR_VERSION_MAJOR_V2
COR_VERSION_MINOR = 0
COR_DELETED_NAME_LENGTH = 8
COR_VTABLEGAP_NAME_LENGTH = 8
NATIVE_TYPE_MAX_CB = 1
COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE= 0xFF
IMAGE_COR_MIH_METHODRVA = 0x01
IMAGE_COR_MIH_EHRVA = 0x02
IMAGE_COR_MIH_BASICBLOCK = 0x08
COR_VTABLE_32BIT =0x01
COR_VTABLE_64BIT =0x02
COR_VTABLE_FROM_UNMANAGED = 0x04
COR_VTABLE_CALL_MOST_DERIVED = 0x10
IMAGE_COR_EATJ_THUNK_SIZE = 32
MAX_CLASS_NAME =1024
MAX_PACKAGE_NAME = 1024

class ReplacesCorHdrNumericDefines(enum.IntFlag):
    COMIMAGE_FLAGS_ILONLY = 0x00000001
    COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
    COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004
    COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008
    COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x00010000
    COR_VERSION_MAJOR_V2 = 2
    COR_VERSION_MAJOR = COR_VERSION_MAJOR_V2
    COR_VERSION_MINOR = 0
    COR_DELETED_NAME_LENGTH = 8
    COR_VTABLEGAP_NAME_LENGTH = 8
    NATIVE_TYPE_MAX_CB = 1
    COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE= 0xFF
    IMAGE_COR_MIH_METHODRVA = 0x01
    IMAGE_COR_MIH_EHRVA = 0x02
    IMAGE_COR_MIH_BASICBLOCK = 0x08
    COR_VTABLE_32BIT = 0x01
    COR_VTABLE_64BIT = 0x02
    COR_VTABLE_FROM_UNMANAGED = 0x04
    COR_VTABLE_CALL_MOST_DERIVED = 0x10
    IMAGE_COR_EATJ_THUNK_SIZE = 32
    MAX_CLASS_NAME = 1024
    MAX_PACKAGE_NAME = 1024

class IMAGE_COR20_HEADER(Structure):
    class EntryUnion(Union):
        _fields_ = [('EntryPointToken', DWORD),
                    ('EntryPointRVA', DWORD)
        ]

    _anonymous_ = ['EntryUnion']
    _fields_ = [('cb', DWORD),
                ('MajorRuntimeVersion', WORD),
                ('MinorRuntimeVersion', WORD),
                ('MetaData', IMAGE_DATA_DIRECTORY),
                ('Flags', DWORD),
                ('EntryUnion', EntryUnion),
                ('Resources', IMAGE_DATA_DIRECTORY),
                ('StrongNameSignature', IMAGE_DATA_DIRECTORY),
                ('CodeManagerTable', IMAGE_DATA_DIRECTORY),
                ('VTableFixups', IMAGE_DATA_DIRECTORY),
                ('ExportAddressTableJumps', IMAGE_DATA_DIRECTORY),
                ('ManagedNativeHeader', IMAGE_DATA_DIRECTORY)
    ]

PIMAGE_COR20_HEADER = POINTER(IMAGE_COR20_HEADER)


def RtlCaptureStackBackTrace(FramesToSkip, FramesToCapture, BackTrace, BackTraceHash) -> int:
    RtlCaptureStackBackTrace = ntdll.RtlCaptureStackBackTrace
    RtlCaptureStackBackTrace.argtypes = [DWORD, DWORD, PVOID, PDWORD]
    RtlCaptureStackBackTrace.restype = WORD
    return RtlCaptureStackBackTrace(FramesToSkip, FramesToCapture, BackTrace, BackTraceHash)


def RtlCaptureContext(ContextRecord):
    RtlCaptureContext = ntdll.RtlCaptureContext
    RtlCaptureContext.argtypes = [PCONTEXT]
    RtlCaptureContext.restype = VOID
    RtlCaptureContext(ContextRecord)


def RtlCompareMemory(Source1, Source2, Length) -> int:
    RtlCompareMemory = ntdll.RtlCompareMemory
    RtlCompareMemory.argtypes = [VOID, VOID, SIZE_T]
    RtlCompareMemory.restype = SIZE_T
    return RtlCompareMemory(Source1, Source2, Length)


def RtlSecureZeroMemory(Destination, Length):
    memset(Destination, 0, Length)


SecureZeroMemory = RtlSecureZeroMemory
CaptureStackBackTrace = RtlCaptureStackBackTrace

if WIN32_WINNT >= 0x0602:
    def RtlAddGrowableFunctionTable(DynamicTable, FunctionTable, MaximumEntryCount, RangeBase, RangeEnd, errcheck: bool = True):
        RtlAddGrowableFunctionTable = ntdll.RtlAddGrowableFunctionTable
        RtlAddGrowableFunctionTable.argtypes = [
            PVOID,
            PRUNTIME_FUNCTION,
            DWORD,
            DWORD
        ]

        RtlAddGrowableFunctionTable.restype = DWORD
        res = RtlAddGrowableFunctionTable(DynamicTable, FunctionTable, MaximumEntryCount, RangeBase, RangeEnd)
        return win32_to_errcheck(res, errcheck)
            

    def RtlGrowFunctionTable(DynamicTable, NewEntryCount):
        RtlGrowFunctionTable = ntdll.RtlGrowFunctionTable
        RtlGrowFunctionTable.argtypes = [PVOID, DWORD]
        RtlGrowFunctionTable.restype = VOID
        RtlGrowFunctionTable(DynamicTable, NewEntryCount)


    def RtlDeleteGrowableFunctionTable(DynamicTable):
        RtlDeleteGrowableFunctionTable = ntdll.RtlDeleteGrowableFunctionTable
        RtlDeleteGrowableFunctionTable.argtypes = [PVOID]
        RtlDeleteGrowableFunctionTable.restype = VOID
        RtlDeleteGrowableFunctionTable(DynamicTable)


def RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress, errcheck: bool = True):
    RtlAddFunctionTable = ntdll.RtlAddFunctionTable
    RtlAddFunctionTable.argtypes = [PRUNTIME_FUNCTION, DWORD, DWORD64]
    RtlAddFunctionTable.restype = BOOLEAN
    res = RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress)
    return win32_to_errcheck(res, errcheck)


def RtlDeleteFunctionTable(FunctionTable, errcheck: bool = True):
    RtlDeleteFunctionTable = kernel32.RtlDeleteFunctionTable
    RtlDeleteFunctionTable.argtypes = [PRUNTIME_FUNCTION]
    RtlDeleteFunctionTable.restype = BOOLEAN
    res = RtlDeleteFunctionTable(FunctionTable)
    return win32_to_errcheck(res, errcheck)


def RtlInstallFunctionTableCallback(
    TableIdentifier, 
    BaseAddress, 
    Length, 
    Callback, 
    Context, 
    OutOfProcessCallbackDll,
    errcheck: bool = True
):
    
    RtlInstallFunctionTableCallback = kernel32.RtlInstallFunctionTableCallback
    RtlInstallFunctionTableCallback.argtypes = [
        DWORD64,
        DWORD64,
        DWORD,
        PGET_RUNTIME_FUNCTION_CALLBACK,
        PVOID,
        PCWSTR
    ]

    RtlInstallFunctionTableCallback.restype = BOOLEAN
    res = RtlInstallFunctionTableCallback(
        TableIdentifier, 
        BaseAddress, 
        Length, 
        Callback, 
        Context, 
        OutOfProcessCallbackDll
    )

    return win32_to_errcheck(res, errcheck)


def RtlRestoreContext(ContextRecord, ExceptionRecord):
    RtlRestoreContext = kernel32.RtlRestoreContext
    RtlRestoreContext.argtypes = [PCONTEXT, _EXCEPTION_RECORD]
    RtlRestoreContext(ContextRecord, ExceptionRecord)


def RtlUnwind(
    TargetFrame, 
    TargetIp, 
    ExceptionRecord, 
    ReturnValue
):
    
    RtlUnwind = kernel32.RtlUnwind
    RtlUnwind.argtypes = [
        PVOID,
        PVOID,
        PEXCEPTION_RECORD,
        PVOID
    ]

    RtlUnwind.restype = VOID
    RtlUnwind(TargetFrame, 
            TargetIp, 
            ExceptionRecord, 
            ReturnValue
    )


def RtlPcToFileHeader(PcValue, BaseOfImage):
    RtlPcToFileHeader = kernel32.RtlPcToFileHeader
    RtlPcToFileHeader.argtypes = [PVOID, POINTER(PVOID)]
    RtlPcToFileHeader.restype = PVOID
    return RtlPcToFileHeader(PcValue, BaseOfImage)



# _x86_64

def RtlLookupFunctionEntry(ControlPc, ImageBase, HistoryTable):
    RtlLookupFunctionEntry = kernel32.RtlLookupFunctionEntry
    RtlLookupFunctionEntry.argtypes = [
        PDWORD64,
        PDWORD64,
        PUNWIND_HISTORY_TABLE
    ]

    RtlLookupFunctionEntry.restype = PRUNTIME_FUNCTION
    return RtlLookupFunctionEntry(ControlPc, ImageBase, HistoryTable)


def RtlUnwindEx(
    TargetFrame, 
    TargetIp, 
    ExceptionRecord, 
    ReturnValue, 
    ContextRecord, 
    HistoryTable
):
    
    RtlUnwindEx = kernel32.RtlUnwindEx
    RtlUnwindEx.argtypes = [
        PVOID,
        PVOID,
        PEXCEPTION_RECORD,
        PVOID,
        PCONTEXT,
        PUNWIND_HISTORY_TABLE
    ]


    RtlUnwindEx(
        TargetFrame, 
        TargetIp, 
        ExceptionRecord, 
        ReturnValue, 
        ContextRecord, 
        HistoryTable
    )


def RtlVirtualUnwind(
    HandlerType, 
    ImageBase, 
    ControlPc, 
    FunctionEntry, 
    ContextRecord,
    HandlerData,
    EstablisherFrame,
    ContextPointers
):
    
    RtlVirtualUnwind = kernel32.RtlVirtualUnwind
    RtlVirtualUnwind.argtypes = [
        DWORD,
        DWORD64,
        DWORD64,
        PRUNTIME_FUNCTION,
        PCONTEXT,
        PVOID,
        PDWORD64,
        PKNONVOLATILE_CONTEXT_POINTERS
    ]

    RtlVirtualUnwind(
        HandlerType, 
        ImageBase, 
        ControlPc, 
        FunctionEntry, 
        ContextRecord,
        HandlerData,
        EstablisherFrame,
        ContextPointers
    )


# WIN64

class _SLIST_ENTRY(Structure):
    _align_ = 16

_SLIST_ENTRY._fields_ = [('Next', POINTER(_SLIST_ENTRY))]

SLIST_ENTRY = _SLIST_ENTRY
PSLIST_ENTRY = POINTER(SLIST_ENTRY)

class _SLIST_HEADER(Structure):
    _align_ = 16
    class AliRegStruct(Structure):
        _fields_ = [('Alignment', ULONGLONG), 
                    ('Region', ULONGLONG)
        ]
    
    class Header8(LittleEndianStructure):
        _fields_ = [('Depth', ULONGLONG, 16),
                    ('Sequence', ULONGLONG, 9),
                    ('NextEntry', ULONGLONG, 39),
                    ('HeaderType', ULONGLONG, 1),
                    ('Init', ULONGLONG, 1),
                    ('Reserved', ULONGLONG, 59),
                    ('Region', ULONGLONG, 3)
        ]
    
    class HeaderX64(LittleEndianStructure):
        _fields_ = [('Depth', ULONGLONG, 16),
                    ('Sequence', ULONGLONG, 48),
                    ('HeaderType', ULONGLONG, 1),
                    ('Reserved', ULONGLONG, 3),
                    ('NextEntry', ULONGLONG, 60)
        ]
    
    _anonymous_ = ['AliRegStruct', 'Header8', 'HeaderX64']
    _fields_ = [('AliRegStruct', AliRegStruct),
                ('Header8', Header8),
                ('HeaderX64', HeaderX64)
    ]

SLIST_HEADER = _SLIST_HEADER
PSLIST_HEADER = POINTER(SLIST_HEADER)


def RtlInitializeSListHead(ListHead: Any) -> None:
    RtlInitializeSListHead = ntdll.RtlInitializeSListHead
    RtlInitializeSListHead.argtypes = [PSLIST_HEADER]
    RtlInitializeSListHead(ListHead)


def RtlFirstEntrySList(ListHead: Any) -> int:
    RtlFirstEntrySList = ntdll.RtlFirstEntrySList
    RtlFirstEntrySList.argtypes = [SLIST_HEADER]
    RtlFirstEntrySList.restype = PSLIST_ENTRY
    return RtlFirstEntrySList(ListHead)


def RtlInterlockedPopEntrySList(ListHead: Any) -> int:
    RtlInterlockedPopEntrySList = ntdll.RtlInterlockedPopEntrySList
    RtlInterlockedPopEntrySList.argtypes = [SLIST_HEADER]
    RtlInterlockedPopEntrySList.restype = PSLIST_ENTRY
    return RtlInterlockedPopEntrySList(ListHead)


def RtlInterlockedPushEntrySList(ListHead: Any, ListEntry: Any) -> int:
    RtlInterlockedPushEntrySList = ntdll.RtlInterlockedPushEntrySList
    RtlInterlockedPushEntrySList.argtypes = [
        PSLIST_HEADER,
        PSLIST_ENTRY
    ]

    RtlInterlockedPushEntrySList.restype = PSLIST_ENTRY
    return RtlInterlockedPushEntrySList(ListHead, ListEntry)


def RtlInterlockedPushListSListEx(ListHead: Any, List: Any, ListEnd: Any, Count: int) -> int:
    RtlInterlockedPushListSListEx = ntdll.RtlInterlockedPushListSListEx
    RtlInterlockedPushListSListEx.argtypes = [
        PSLIST_HEADER,
        PSLIST_ENTRY,
        PSLIST_ENTRY,
        DWORD
    ]

    RtlInterlockedPushListSListEx.restype = PSLIST_ENTRY
    return RtlInterlockedPushListSListEx(ListHead, List, ListEnd, Count)


def RtlInterlockedFlushSList(ListHead: Any) -> int:
    RtlInterlockedFlushSList = ntdll.RtlInterlockedFlushSList
    RtlInterlockedFlushSList.argtypes = [PSLIST_HEADER]
    RtlInterlockedFlushSList.restype = PSLIST_ENTRY
    return RtlInterlockedFlushSList(ListHead)


def RtlQueryDepthSList(ListHead: Any) -> int:
    RtlQueryDepthSList = ntdll.RtlQueryDepthSList
    RtlQueryDepthSList.argtypes = [PSLIST_HEADER]
    RtlQueryDepthSList.restype = WORD
    return RtlQueryDepthSList(ListHead)


class _RTL_RUN_ONCE(Structure):
    _fields_ = [('Ptr', PVOID)]

RTL_RUN_ONCE = _RTL_RUN_ONCE
PRTL_RUN_ONCE = POINTER(RTL_RUN_ONCE)

RTL_RUN_ONCE_INIT= 0
RTL_RUN_ONCE_CHECK_ONLY= 1
RTL_RUN_ONCE_ASYNC= 2
RTL_RUN_ONCE_INIT_FAILED= 4
RTL_RUN_ONCE_CTX_RESERVED_BITS= 2

class _RTL_BARRIER(Structure):
    _fields_ = [('Reserved1', DWORD),
                ('Reserved2', DWORD),
                ('Reserved3', ULONG_PTR),
                ('Reserved4', DWORD),
                ('Reserved5', DWORD)
    ]

RTL_BARRIER = _RTL_BARRIER
PRTL_BARRIER = POINTER(RTL_BARRIER)

FAST_FAIL_LEGACY_GS_VIOLATION = 0
FAST_FAIL_VTGUARD_CHECK_FAILURE = 1
FAST_FAIL_STACK_COOKIE_CHECK_FAILURE = 2
FAST_FAIL_CORRUPT_LIST_ENTRY = 3
FAST_FAIL_INCORRECT_STACK = 4
FAST_FAIL_INVALID_ARG = 5
FAST_FAIL_GS_COOKIE_INIT = 6
FAST_FAIL_FATAL_APP_EXIT = 7
FAST_FAIL_RANGE_CHECK_FAILURE = 8
FAST_FAIL_UNSAFE_REGISTRY_ACCESS = 9
FAST_FAIL_INVALID_FAST_FAIL_CODE = 0xffffffff

HEAP_NO_SERIALIZE = 0x00000001
HEAP_GROWABLE = 0x00000002
HEAP_GENERATE_EXCEPTIONS = 0x00000004
HEAP_ZERO_MEMORY = 0x00000008
HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010
HEAP_TAIL_CHECKING_ENABLED = 0x00000020
HEAP_FREE_CHECKING_ENABLED = 0x00000040
HEAP_DISABLE_COALESCE_ON_FREE = 0x00000080
HEAP_CREATE_ALIGN_16 = 0x00010000
HEAP_CREATE_ENABLE_TRACING = 0x00020000
HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
HEAP_MAXIMUM_TAG = 0x0FFF
HEAP_PSEUDO_TAG_FLAG = 0x8000
HEAP_TAG_SHIFT = 18


def HEAP_MAKE_TAG_FLAGS(b: int, o: int) -> int:
    return DWORD(b + (o << 18)).value


IS_TEXT_UNICODE_ASCII16 = 0x0001
IS_TEXT_UNICODE_REVERSE_ASCII16 = 0x0010

IS_TEXT_UNICODE_STATISTICS = 0x0002
IS_TEXT_UNICODE_REVERSE_STATISTICS = 0x0020

IS_TEXT_UNICODE_CONTROLS = 0x0004
IS_TEXT_UNICODE_REVERSE_CONTROLS = 0x0040

IS_TEXT_UNICODE_SIGNATURE = 0x0008
IS_TEXT_UNICODE_REVERSE_SIGNATURE = 0x0080

IS_TEXT_UNICODE_ILLEGAL_CHARS = 0x0100
IS_TEXT_UNICODE_ODD_LENGTH = 0x0200
IS_TEXT_UNICODE_DBCS_LEADBYTE = 0x0400
IS_TEXT_UNICODE_NULL_BYTES = 0x1000

IS_TEXT_UNICODE_UNICODE_MASK = 0x000F
IS_TEXT_UNICODE_REVERSE_MASK = 0x00F0
IS_TEXT_UNICODE_NOT_UNICODE_MASK = 0x0F00
IS_TEXT_UNICODE_NOT_ASCII_MASK = 0xF000

COMPRESSION_FORMAT_NONE = 0x0000
COMPRESSION_FORMAT_DEFAULT = 0x0001
COMPRESSION_FORMAT_LZNT1 = 0x0002
COMPRESSION_FORMAT_XPRESS = 0x0003
COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004
COMPRESSION_ENGINE_STANDARD = 0x0000
COMPRESSION_ENGINE_MAXIMUM = 0x0100
COMPRESSION_ENGINE_HIBER = 0x0200

def RtlEqualMemory(Destination, Source, Length: int): return memcmp(Destination, Source, Length)
def RtlMoveMemory(Destination, Source, Length: int): return memmove(Destination, Source, Length)
def RtlCopyMemory(Destination, Source, Length: int): return memcpy(Destination, Source, Length)
def RtlFillMemory(Destination, Length: int, Fill: int): return memset(Destination, Fill, Length)
def RtlZeroMemory(Destination, Length: int): memset(Destination, 0, Length)

class _MESSAGE_RESOURCE_ENTRY(Structure):
    _fields_ = [('Length', WORD),
                ('Flags', WORD),
                ('Text', BYTE * 1)
    ]

MESSAGE_RESOURCE_ENTRY = _MESSAGE_RESOURCE_ENTRY
PMESSAGE_RESOURCE_ENTRY = POINTER(MESSAGE_RESOURCE_ENTRY)

SEF_DACL_AUTO_INHERIT = 0x01
SEF_SACL_AUTO_INHERIT = 0x02
SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT = 0x04
SEF_AVOID_PRIVILEGE_CHECK = 0x08
SEF_AVOID_OWNER_CHECK = 0x10
SEF_DEFAULT_OWNER_FROM_PARENT = 0x20
SEF_DEFAULT_GROUP_FROM_PARENT = 0x40
SEF_MACL_NO_WRITE_UP = 0x100
SEF_MACL_NO_READ_UP = 0x200
SEF_MACL_NO_EXECUTE_UP = 0x400
SEF_AVOID_OWNER_RESTRICTION = 0x1000

SEF_MACL_VALID_FLAGS = (SEF_MACL_NO_WRITE_UP | 
                        SEF_MACL_NO_READ_UP | 
                        SEF_MACL_NO_EXECUTE_UP
)

MESSAGE_RESOURCE_UNICODE = 0x0001

class _MESSAGE_RESOURCE_BLOCK(Structure):
    _fields_ = [('LowId', DWORD),
                ('HighId', DWORD),
                ('OffsetToEntries', DWORD)
    ]

MESSAGE_RESOURCE_BLOCK = _MESSAGE_RESOURCE_BLOCK
PMESSAGE_RESOURCE_BLOCK = POINTER(MESSAGE_RESOURCE_BLOCK)

class _MESSAGE_RESOURCE_DATA(Structure):
    _fields_ = [('NumberOfBlocks', DWORD), 
                ('Blocks', MESSAGE_RESOURCE_BLOCK * 1)
    ]

MESSAGE_RESOURCE_DATA = _MESSAGE_RESOURCE_DATA
PMESSAGE_RESOURCE_DATA = POINTER(MESSAGE_RESOURCE_DATA)

class _OSVERSIONINFOA(Structure):
    _fields_ = [('dwOSVersionInfoSize', DWORD),
                ('dwMajorVersion', DWORD),
                ('dwMinorVersion', DWORD),
                ('dwBuildNumber', DWORD),
                ('dwPlatformId', DWORD),
                ('szCSDVersion', CHAR * 128)
    ]

OSVERSIONINFOA = _OSVERSIONINFOA
POSVERSIONINFOA = POINTER(OSVERSIONINFOA)
LPOSVERSIONINFOA = POSVERSIONINFOA

class _OSVERSIONINFOW(Structure):
    _fields_ = [('dwOSVersionInfoSize', DWORD),
                ('dwMajorVersion', DWORD),
                ('dwMinorVersion', DWORD),
                ('dwBuildNumber', DWORD),
                ('dwPlatformId', DWORD),
                ('szCSDVersion', WCHAR * 128)
    ]

OSVERSIONINFOW = _OSVERSIONINFOW
POSVERSIONINFOW = POINTER(OSVERSIONINFOW)
LPOSVERSIONINFOW = POSVERSIONINFOW
RTL_OSVERSIONINFOW = OSVERSIONINFOW

class _OSVERSIONINFOEXA(Structure):
    _fields_ = [('dwOSVersionInfoSize', DWORD),
                ('dwMajorVersion', DWORD),
                ('dwMinorVersion', DWORD),
                ('dwBuildNumber', DWORD),
                ('dwPlatformId', DWORD),
                ('szCSDVersion', CHAR * 128),
                ('wServicePackMajor', WORD),
                ('wServicePackMinor', WORD),
                ('wSuiteMask', WORD),
                ('wProductType', BYTE),
                ('wReserved', BYTE)
    ]

OSVERSIONINFOEXA = _OSVERSIONINFOEXA
POSVERSIONINFOEXA = POINTER(OSVERSIONINFOEXA)
LPOSVERSIONINFOEXA = POSVERSIONINFOEXA

class _OSVERSIONINFOEXW(Structure):
    _fields_ = [('dwOSVersionInfoSize', DWORD),
                ('dwMajorVersion', DWORD),
                ('dwMinorVersion', DWORD),
                ('dwBuildNumber', DWORD),
                ('dwPlatformId', DWORD),
                ('szCSDVersion', WCHAR * 128),
                ('wServicePackMajor', WORD),
                ('wServicePackMinor', WORD),
                ('wSuiteMask', WORD),
                ('wProductType', BYTE),
                ('wReserved', BYTE)
    ]

OSVERSIONINFOEXW = _OSVERSIONINFOEXW
POSVERSIONINFOEXW = POINTER(OSVERSIONINFOEXW)
LPOSVERSIONINFOEXW = POSVERSIONINFOEXW

VER_EQUAL = 1
VER_GREATER = 2
VER_GREATER_EQUAL = 3
VER_LESS = 4
VER_LESS_EQUAL = 5
VER_AND = 6
VER_OR = 7

VER_CONDITION_MASK = 7
VER_NUM_BITS_PER_CONDITION_MASK = 3

VER_MINORVERSION = 0x0000001
VER_MAJORVERSION = 0x0000002
VER_BUILDNUMBER = 0x0000004
VER_PLATFORMID = 0x0000008
VER_SERVICEPACKMINOR = 0x0000010
VER_SERVICEPACKMAJOR = 0x0000020
VER_SUITENAME = 0x0000040
VER_PRODUCT_TYPE = 0x0000080

VER_NT_WORKSTATION = 0x0000001
VER_NT_DOMAIN_CONTROLLER = 0x0000002
VER_NT_SERVER = 0x0000003

VER_PLATFORM_WIN32s = 0
VER_PLATFORM_WIN32_WINDOWS = 1
VER_PLATFORM_WIN32_NT = 2


def VerSetConditionMask(ConditionMask, TypeMask, Condition):
    VerSetConditionMask = ntdll.VerSetConditionMask
    VerSetConditionMask.argtypes = [ULONGLONG, DWORD, BYTE]
    VerSetConditionMask.restype = ULONGLONG
    res = VerSetConditionMask(ConditionMask, TypeMask, Condition)
    return res


VER_SET_CONDITION = VerSetConditionMask


def RtlGetProductInfo(OSMajorVersion, OSMinorVersion, SpMajorVersion, SpMinorVersion, ReturnedProductType):
    RtlGetProductInfo = ntdll.RtlGetProductInfo
    RtlGetProductInfo.argtypes = [DWORD, DWORD, DWORD, DWORD, PDWORD]
    RtlGetProductInfo.restype = BOOLEAN
    res = RtlGetProductInfo(OSMajorVersion, OSMinorVersion, SpMajorVersion, SpMinorVersion, ReturnedProductType)
    return res


RTL_UMS_VERSION = 0x0100

UmsThreadInvalidInfoClass = 0
UmsThreadUserContext = 1
UmsThreadPriority = 2
UmsThreadAffinity = 3
UmsThreadTeb = 4
UmsThreadIsSuspended = 5
UmsThreadIsTerminated = 6
UmsThreadMaxInfoClass = 7

class _RTL_UMS_THREAD_INFO_CLASS(enum.IntFlag):
    UmsThreadInvalidInfoClass = 0
    UmsThreadUserContext = 1
    UmsThreadPriority = 2
    UmsThreadAffinity = 3
    UmsThreadTeb = 4
    UmsThreadIsSuspended = 5
    UmsThreadIsTerminated = 6
    UmsThreadMaxInfoClass = 7

RTL_UMS_THREAD_INFO_CLASS = _RTL_UMS_THREAD_INFO_CLASS
PRTL_UMS_THREAD_INFO_CLASS = RTL_UMS_THREAD_INFO_CLASS

UmsSchedulerStartup = 0
UmsSchedulerThreadBlocked = 1
UmsSchedulerThreadYield = 2

class _RTL_UMS_SCHEDULER_REASON(enum.IntFlag):
    UmsSchedulerStartup = 0
    UmsSchedulerThreadBlocked = 1
    UmsSchedulerThreadYield = 2

RTL_UMS_SCHEDULER_REASON = _RTL_UMS_SCHEDULER_REASON
PRTL_UMS_SCHEDULER_REASON = RTL_UMS_SCHEDULER_REASON

RTL_UMS_SCHEDULER_ENTRY_POINT = NTAPI(VOID, UINT, ULONG_PTR, PVOID)
PRTL_UMS_SCHEDULER_ENTRY_POINT = POINTER(RTL_UMS_SCHEDULER_ENTRY_POINT)

if WIN32_WINNT >= 0x0602:
    def IS_VALIDATION_ENABLED(C: int, L: int) -> int:
        return C & L
    

    VRL_PREDEFINED_CLASS_BEGIN = 1
    VRL_CUSTOM_CLASS_BEGIN =  1 << 8
    VRL_CLASS_CONSISTENCY = VRL_PREDEFINED_CLASS_BEGIN
    VRL_ENABLE_KERNEL_BREAKS =  1 << 31

    CTMF_INCLUDE_APPCONTAINER = 0x1
    CTMF_VALID_FLAGS = 0x1

    RtlCrc32 = NTAPI(DWORD, VOID, SIZE_T, DWORD)
    RtlCrc64 = NTAPI(ULONGLONG, VOID, SIZE_T, ULONGLONG)

class _RTL_CRITICAL_SECTION(Structure):
    pass

class _RTL_CRITICAL_SECTION_DEBUG(Structure):
    _fields_ = [('Type', WORD),
                ('CreatorBackTraceIndex', WORD),
                ('CriticalSection', POINTER(_RTL_CRITICAL_SECTION)),
                ('ProcessLocksList', LIST_ENTRY),
                ('EntryCount', DWORD),
                ('ContentionCount', DWORD),
                ('Flags', DWORD),
                ('CreatorBackTraceIndexHigh', WORD),
                ('SpareWORD', WORD)
    ]

RTL_CRITICAL_SECTION_DEBUG = _RTL_CRITICAL_SECTION_DEBUG
PRTL_CRITICAL_SECTION_DEBUG = POINTER(RTL_CRITICAL_SECTION_DEBUG)

class _RTL_CRITICAL_SECTION(Structure):
    _fields_ = [('DebugInfo', PRTL_CRITICAL_SECTION_DEBUG),
                ('LockCount', LONG),
                ('RecursionCount', LONG),
                ('OwningThread', HANDLE),
                ('LockSemaphore', HANDLE),
                ('SpinCount', ULONG_PTR)
    ]

RTL_CRITICAL_SECTION = _RTL_CRITICAL_SECTION
PRTL_CRITICAL_SECTION = POINTER(RTL_CRITICAL_SECTION)

RTL_CRITSECT_TYPE = 0
RTL_RESOURCE_TYPE = 1

RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO = 0x01000000
RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN = 0x02000000
RTL_CRITICAL_SECTION_FLAG_STATIC_INIT = 0x04000000
RTL_CRITICAL_SECTION_FLAG_RESOURCE_TYPE = 0x08000000
RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO = 0x10000000
RTL_CRITICAL_SECTION_ALL_FLAG_BITS = 0xff000000

RTL_CRITICAL_SECTION_FLAG_RESERVED = (RTL_CRITICAL_SECTION_ALL_FLAG_BITS & (~(RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO | 
                                                                              RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN | 
                                                                              RTL_CRITICAL_SECTION_FLAG_STATIC_INIT | 
                                                                              RTL_CRITICAL_SECTION_FLAG_RESOURCE_TYPE | 
                                                                              RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO))
)

RTL_CRITICAL_SECTION_DEBUG_FLAG_STATIC_INIT = 0x00000001

class RTL_CRITICAL_SECTION(Structure):
    _fields_ = [('DebugInfo', PRTL_CRITICAL_SECTION_DEBUG),
                ('LockCount', LONG),
                ('RecursionCount', LONG),
                ('OwningThread', HANDLE),
                ('LockSemaphore', HANDLE),
                ('SpinCount', ULONG_PTR)
    ]

class _RTL_SRWLOCK(Structure):
    _fields_ = [('Ptr', PVOID)]

RTL_SRWLOCK = _RTL_SRWLOCK
PRTL_SRWLOCK = POINTER(RTL_SRWLOCK)

_RTL_CONDITION_VARIABLE = RTL_SRWLOCK
RTL_CONDITION_VARIABLE = _RTL_CONDITION_VARIABLE
PRTL_CONDITION_VARIABLE = POINTER(RTL_CONDITION_VARIABLE)

RTL_SRWLOCK_INIT = 0
RTL_CONDITION_VARIABLE_INIT = 0

RTL_CONDITION_VARIABLE_LOCKMODE_SHARED = 0x1

PAPCFUNC = POINTER(NTAPI(VOID, ULONG_PTR))
PVECTORED_EXCEPTION_HANDLER = POINTER(NTAPI(LONG, _EXCEPTION_POINTERS))

HeapCompatibilityInformation = 0
HeapEnableTerminationOnCorruption = 1

class _HEAP_INFORMATION_CLASS(enum.IntFlag):
    HeapCompatibilityInformation = 0
    HeapEnableTerminationOnCorruption = 1

HEAP_INFORMATION_CLASS = _HEAP_INFORMATION_CLASS

WORKERCALLBACKFUNC = NTAPI(VOID, PVOID)
APC_CALLBACK_FUNCTION = NTAPI(VOID, DWORD, PVOID, PVOID)
WAITORTIMERCALLBACKFUNC = NTAPI(VOID, PVOID, BOOLEAN)
WAITORTIMERCALLBACK = WAITORTIMERCALLBACKFUNC
PFLS_CALLBACK_FUNCTION = NTAPI(VOID, PVOID)
PSECURE_MEMORY_CACHE_CALLBACK = NTAPI(BOOLEAN, PVOID, SIZE_T)

WT_EXECUTEDEFAULT = 0x00000000
WT_EXECUTEINIOTHREAD = 0x00000001
WT_EXECUTEINUITHREAD = 0x00000002
WT_EXECUTEINWAITTHREAD = 0x00000004
WT_EXECUTEONLYONCE = 0x00000008
WT_EXECUTEINTIMERTHREAD = 0x00000020
WT_EXECUTELONGFUNCTION = 0x00000010
WT_EXECUTEINPERSISTENTIOTHREAD = 0x00000040
WT_EXECUTEINPERSISTENTTHREAD = 0x00000080
WT_TRANSFER_IMPERSONATION = 0x00000100


def WT_SET_MAX_THREADPOOL_THREADS(Flags: int, Limit: int) -> int:
    return Flags | (Limit << 16)


WT_EXECUTEDELETEWAIT = 0x00000008
WT_EXECUTEINLONGTHREAD = 0x00000010

ActivationContextBasicInformation = 1
ActivationContextDetailedInformation = 2
AssemblyDetailedInformationInActivationContext = 3
FileInformationInAssemblyOfAssemblyInActivationContext = 4
RunlevelInformationInActivationContext = 5
CompatibilityInformationInActivationContext = 6
ActivationContextManifestResourceName = 7
MaxActivationContextInfoClass = 8
AssemblyDetailedInformationInActivationContxt = 3
FileInformationInAssemblyOfAssemblyInActivationContxt = 4

class _ACTIVATION_CONTEXT_INFO_CLASS(enum.IntFlag):
    ActivationContextBasicInformation = 1
    ActivationContextDetailedInformation = 2
    AssemblyDetailedInformationInActivationContext = 3
    FileInformationInAssemblyOfAssemblyInActivationContext = 4
    RunlevelInformationInActivationContext = 5
    CompatibilityInformationInActivationContext = 6
    ActivationContextManifestResourceName = 7
    MaxActivationContextInfoClass = 8
    AssemblyDetailedInformationInActivationContxt = 3
    FileInformationInAssemblyOfAssemblyInActivationContxt = 4

ACTIVATION_CONTEXT_INFO_CLASS = _ACTIVATION_CONTEXT_INFO_CLASS

ACTCTX_RUN_LEVEL_UNSPECIFIED = 0,
ACTCTX_RUN_LEVEL_AS_INVOKER = 1
ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE = 2
ACTCTX_RUN_LEVEL_REQUIRE_ADMIN = 3
ACTCTX_RUN_LEVEL_NUMBERS = 4

class ACTCTX_REQUESTED_RUN_LEVEL(enum.IntFlag):
    ACTCTX_RUN_LEVEL_UNSPECIFIED = 0,
    ACTCTX_RUN_LEVEL_AS_INVOKER = 1
    ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE = 2
    ACTCTX_RUN_LEVEL_REQUIRE_ADMIN = 3
    ACTCTX_RUN_LEVEL_NUMBERS = 4

ACTCTX_COMPATIBILITY_ELEMENT_TYPE_UNKNOWN = 0,
ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS = 1
ACTCTX_COMPATIBILITY_ELEMENT_TYPE_MITIGATION = 2

class ACTCTX_COMPATIBILITY_ELEMENT_TYPE(enum.IntFlag):
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_UNKNOWN = 0,
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS = 1
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_MITIGATION = 2

class _ACTIVATION_CONTEXT_QUERY_INDEX(Structure):
    _fields_ = [('ulAssemblyIndex', DWORD),
                ('ulFileIndexInAssembly', DWORD)
    ]

ACTIVATION_CONTEXT_QUERY_INDEX = _ACTIVATION_CONTEXT_QUERY_INDEX
PACTIVATION_CONTEXT_QUERY_INDEX = POINTER(ACTIVATION_CONTEXT_QUERY_INDEX)

class _ASSEMBLY_FILE_DETAILED_INFORMATION(Structure):
    _fields_ = [('ulFlags', DWORD),
                ('ulFilenameLength', DWORD),
                ('ulPathLength', DWORD),
                ('lpFileName', PCWSTR),
                ('lpFilePath', PCWSTR)
    ]

ASSEMBLY_FILE_DETAILED_INFORMATION = _ASSEMBLY_FILE_DETAILED_INFORMATION
PASSEMBLY_FILE_DETAILED_INFORMATION = POINTER(ASSEMBLY_FILE_DETAILED_INFORMATION)

class _ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION(Structure):
    _fields_ = [('ulFlags', DWORD),
                ('ulEncodedAssemblyIdentityLength', DWORD),
                ('ulManifestPathType', DWORD),
                ('ulManifestPathLength', DWORD),
                ('liManifestLastWriteTime', LARGE_INTEGER),
                ('ulPolicyPathType', DWORD),
                ('ulPolicyPathLength', DWORD),
                ('liPolicyLastWriteTime', LARGE_INTEGER),
                ('ulMetadataSatelliteRosterIndex', DWORD),
                ('ulManifestVersionMajor', DWORD),
                ('ulManifestVersionMinor', DWORD),
                ('ulPolicyVersionMajor', DWORD),
                ('ulPolicyVersionMinor', DWORD),
                ('ulAssemblyDirectoryNameLength', DWORD),
                ('lpAssemblyEncodedAssemblyIdentity', PCWSTR),
                ('lpAssemblyManifestPath', PCWSTR),
                ('lpAssemblyPolicyPath', PCWSTR),
                ('lpAssemblyDirectoryName', PCWSTR),
                ('ulFileCount', DWORD)
    ]

ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION = _ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION
PACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION = POINTER(ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION)

class _ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION(Structure):
    _fields_ = [('ulFlags', DWORD),
                ('RunLevel', UINT),
                ('UiAccess', DWORD)
    ]

ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION = _ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION
PACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION = POINTER(ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION)

class _COMPATIBILITY_CONTEXT_ELEMENT(Structure):
    _fields_ = [('Id', GUID),
                ('Type', UINT)
    ]

COMPATIBILITY_CONTEXT_ELEMENT = _COMPATIBILITY_CONTEXT_ELEMENT
PCOMPATIBILITY_CONTEXT_ELEMENT = POINTER(COMPATIBILITY_CONTEXT_ELEMENT)

class _ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION(Structure):
    _fields_ = [('ElementCount', DWORD),
                ('Elements', COMPATIBILITY_CONTEXT_ELEMENT)
    ]

ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION = _ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION
PACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION = POINTER(ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION)

MAX_SUPPORTED_OS_NUM = 4

class _SUPPORTED_OS_INFO(Structure):
    _fields_ = [('OsCount', WORD),
                ('MitigationExist', WORD),
                ('OsList', WORD * MAX_SUPPORTED_OS_NUM)
    ]

SUPPORTED_OS_INFO = _SUPPORTED_OS_INFO
PSUPPORTED_OS_INFO = POINTER(SUPPORTED_OS_INFO)

class _ACTIVATION_CONTEXT_DETAILED_INFORMATION(Structure):
    _fields_ = [('dwFlags', DWORD),
                ('ulFormatVersion', DWORD),
                ('ulAssemblyCount', DWORD),
                ('ulRootManifestPathType', DWORD),
                ('ulRootManifestPathChars', DWORD),
                ('ulRootConfigurationPathType', DWORD),
                ('ulRootConfigurationPathChars', DWORD),
                ('ulAppDirPathType', DWORD),
                ('ulAppDirPathChars', DWORD),
                ('lpRootManifestPath', PCWSTR),
                ('lpRootConfigurationPath', PCWSTR),
                ('lpAppDirPath', PCWSTR)
    ]

ACTIVATION_CONTEXT_DETAILED_INFORMATION = _ACTIVATION_CONTEXT_DETAILED_INFORMATION
PACTIVATION_CONTEXT_DETAILED_INFORMATION = POINTER(ACTIVATION_CONTEXT_DETAILED_INFORMATION)

PCACTIVATION_CONTEXT_QUERY_INDEX = POINTER(_ACTIVATION_CONTEXT_QUERY_INDEX)
PCASSEMBLY_FILE_DETAILED_INFORMATION = POINTER(ASSEMBLY_FILE_DETAILED_INFORMATION)
PCACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION = POINTER(_ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION)
PCACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION = POINTER(_ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION)
PCCOMPATIBILITY_CONTEXT_ELEMENT = POINTER(_COMPATIBILITY_CONTEXT_ELEMENT)
PCACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION = POINTER(_ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION)
PCACTIVATION_CONTEXT_DETAILED_INFORMATION = POINTER(_ACTIVATION_CONTEXT_DETAILED_INFORMATION)

ACTIVATIONCONTEXTINFOCLASS = ACTIVATION_CONTEXT_INFO_CLASS

ACTIVATION_CONTEXT_PATH_TYPE_NONE = 1
ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE = 2
ACTIVATION_CONTEXT_PATH_TYPE_URL = 3
ACTIVATION_CONTEXT_PATH_TYPE_ASSEMBLYREF = 4

_ASSEMBLY_DLL_REDIRECTION_DETAILED_INFORMATION = _ASSEMBLY_FILE_DETAILED_INFORMATION
ASSEMBLY_DLL_REDIRECTION_DETAILED_INFORMATION = ASSEMBLY_FILE_DETAILED_INFORMATION
PASSEMBLY_DLL_REDIRECTION_DETAILED_INFORMATION = PASSEMBLY_FILE_DETAILED_INFORMATION
PCASSEMBLY_DLL_REDIRECTION_DETAILED_INFORMATION = PCASSEMBLY_FILE_DETAILED_INFORMATION

INVALID_OS_COUNT = 0xffff

CREATE_BOUNDARY_DESCRIPTOR_ADD_APPCONTAINER_SID = 0x1

RTL_VERIFIER_DLL_LOAD_CALLBACK = NTAPI(VOID, PWSTR, PVOID, SIZE_T, PVOID)
RTL_VERIFIER_DLL_UNLOAD_CALLBACK = NTAPI(VOID, PWSTR, PVOID, SIZE_T, PVOID)
RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK = NTAPI(VOID, PVOID, SIZE_T)

class _RTL_VERIFIER_THUNK_DESCRIPTOR(Structure):
    _fields_ = [('ThunkName', PCHAR),
                ('ThunkOldAddress', PVOID),
                ('ThunkNewAddress', PVOID)
    ]

RTL_VERIFIER_THUNK_DESCRIPTOR = _RTL_VERIFIER_THUNK_DESCRIPTOR
PRTL_VERIFIER_THUNK_DESCRIPTOR = POINTER(RTL_VERIFIER_THUNK_DESCRIPTOR)

class _RTL_VERIFIER_DLL_DESCRIPTOR(Structure):
    _fields_ = [('DllName', PWCHAR),
                ('DllFlags', DWORD),
                ('DllAddress', PVOID),
                ('DllThunks', PRTL_VERIFIER_THUNK_DESCRIPTOR)
    ]

RTL_VERIFIER_DLL_DESCRIPTOR = _RTL_VERIFIER_DLL_DESCRIPTOR
PRTL_VERIFIER_DLL_DESCRIPTOR = POINTER(RTL_VERIFIER_DLL_DESCRIPTOR)

class _RTL_VERIFIER_PROVIDER_DESCRIPTOR(Structure):
    _fields_ = [('Length', DWORD),
                ('ProviderDlls', PRTL_VERIFIER_DLL_DESCRIPTOR),
                ('ProviderDllLoadCallback', RTL_VERIFIER_DLL_LOAD_CALLBACK),
                ('ProviderDllUnloadCallback', RTL_VERIFIER_DLL_UNLOAD_CALLBACK),
                ('VerifierImage', PWSTR),
                ('VerifierFlags', DWORD),
                ('VerifierDebug', DWORD),
                ('RtlpGetStackTraceAddress', PVOID),
                ('RtlpDebugPageHeapCreate', PVOID),
                ('RtlpDebugPageHeapDestroy', PVOID),
                ('ProviderNtdllHeapFreeCallback', RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK)
    ]

RTL_VERIFIER_PROVIDER_DESCRIPTOR = _RTL_VERIFIER_PROVIDER_DESCRIPTOR
PRTL_VERIFIER_PROVIDER_DESCRIPTOR = POINTER(RTL_VERIFIER_PROVIDER_DESCRIPTOR)

RTL_VRF_FLG_FULL_PAGE_HEAP = 0x00000001
RTL_VRF_FLG_RESERVED_DONOTUSE = 0x00000002
RTL_VRF_FLG_HANDLE_CHECKS = 0x00000004
RTL_VRF_FLG_STACK_CHECKS = 0x00000008
RTL_VRF_FLG_APPCOMPAT_CHECKS = 0x00000010
RTL_VRF_FLG_TLS_CHECKS = 0x00000020
RTL_VRF_FLG_DIRTY_STACKS = 0x00000040
RTL_VRF_FLG_RPC_CHECKS = 0x00000080
RTL_VRF_FLG_COM_CHECKS = 0x00000100
RTL_VRF_FLG_DANGEROUS_APIS = 0x00000200
RTL_VRF_FLG_RACE_CHECKS = 0x00000400
RTL_VRF_FLG_DEADLOCK_CHECKS = 0x00000800
RTL_VRF_FLG_FIRST_CHANCE_EXCEPTION_CHECKS = 0x00001000
RTL_VRF_FLG_VIRTUAL_MEM_CHECKS = 0x00002000
RTL_VRF_FLG_ENABLE_LOGGING = 0x00004000
RTL_VRF_FLG_FAST_FILL_HEAP = 0x00008000
RTL_VRF_FLG_VIRTUAL_SPACE_TRACKING = 0x00010000
RTL_VRF_FLG_ENABLED_SYSTEM_WIDE = 0x00020000
RTL_VRF_FLG_MISCELLANEOUS_CHECKS = 0x00020000
RTL_VRF_FLG_LOCK_CHECKS = 0x00040000

APPLICATION_VERIFIER_INTERNAL_ERROR = 0x80000000
APPLICATION_VERIFIER_INTERNAL_WARNING = 0x40000000
APPLICATION_VERIFIER_NO_BREAK = 0x20000000
APPLICATION_VERIFIER_CONTINUABLE_BREAK = 0x10000000

APPLICATION_VERIFIER_UNKNOWN_ERROR = 0x0001
APPLICATION_VERIFIER_ACCESS_VIOLATION = 0x0002
APPLICATION_VERIFIER_UNSYNCHRONIZED_ACCESS = 0x0003
APPLICATION_VERIFIER_EXTREME_SIZE_REQUEST = 0x0004
APPLICATION_VERIFIER_BAD_HEAP_HANDLE = 0x0005
APPLICATION_VERIFIER_SWITCHED_HEAP_HANDLE = 0x0006
APPLICATION_VERIFIER_DOUBLE_FREE = 0x0007
APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK = 0x0008
APPLICATION_VERIFIER_DESTROY_PROCESS_HEAP = 0x0009
APPLICATION_VERIFIER_UNEXPECTED_EXCEPTION = 0x000A
APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_EXCEPTION_RAISED_FOR_HEADER = 0x000B
APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_EXCEPTION_RAISED_FOR_PROBING = 0x000C
APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_HEADER = 0x000D
APPLICATION_VERIFIER_CORRUPTED_FREED_HEAP_BLOCK = 0x000E
APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_SUFFIX = 0x000F
APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_START_STAMP = 0x0010
APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_END_STAMP = 0x0011
APPLICATION_VERIFIER_CORRUPTED_HEAP_BLOCK_PREFIX = 0x0012
APPLICATION_VERIFIER_FIRST_CHANCE_ACCESS_VIOLATION = 0x0013
APPLICATION_VERIFIER_CORRUPTED_HEAP_LIST = 0x0014

APPLICATION_VERIFIER_TERMINATE_THREAD_CALL = 0x0100
APPLICATION_VERIFIER_STACK_OVERFLOW = 0x0101
APPLICATION_VERIFIER_INVALID_EXIT_PROCESS_CALL = 0x0102

APPLICATION_VERIFIER_EXIT_THREAD_OWNS_LOCK = 0x0200
APPLICATION_VERIFIER_LOCK_IN_UNLOADED_DLL = 0x0201
APPLICATION_VERIFIER_LOCK_IN_FREED_HEAP = 0x0202
APPLICATION_VERIFIER_LOCK_DOUBLE_INITIALIZE = 0x0203
APPLICATION_VERIFIER_LOCK_IN_FREED_MEMORY = 0x0204
APPLICATION_VERIFIER_LOCK_CORRUPTED = 0x0205
APPLICATION_VERIFIER_LOCK_INVALID_OWNER = 0x0206
APPLICATION_VERIFIER_LOCK_INVALID_RECURSION_COUNT = 0x0207
APPLICATION_VERIFIER_LOCK_INVALID_LOCK_COUNT = 0x0208
APPLICATION_VERIFIER_LOCK_OVER_RELEASED = 0x0209
APPLICATION_VERIFIER_LOCK_NOT_INITIALIZED = 0x0210
APPLICATION_VERIFIER_LOCK_ALREADY_INITIALIZED = 0x0211
APPLICATION_VERIFIER_LOCK_IN_FREED_VMEM = 0x0212
APPLICATION_VERIFIER_LOCK_IN_UNMAPPED_MEM = 0x0213
APPLICATION_VERIFIER_THREAD_NOT_LOCK_OWNER = 0x0214

APPLICATION_VERIFIER_INVALID_HANDLE = 0x0300
APPLICATION_VERIFIER_INVALID_TLS_VALUE = 0x0301
APPLICATION_VERIFIER_INCORRECT_WAIT_CALL = 0x0302
APPLICATION_VERIFIER_NULL_HANDLE = 0x0303
APPLICATION_VERIFIER_WAIT_IN_DLLMAIN = 0x0304

APPLICATION_VERIFIER_COM_ERROR = 0x0400
APPLICATION_VERIFIER_COM_API_IN_DLLMAIN = 0x0401
APPLICATION_VERIFIER_COM_UNHANDLED_EXCEPTION = 0x0402
APPLICATION_VERIFIER_COM_UNBALANCED_COINIT = 0x0403
APPLICATION_VERIFIER_COM_UNBALANCED_OLEINIT = 0x0404
APPLICATION_VERIFIER_COM_UNBALANCED_SWC = 0x0405
APPLICATION_VERIFIER_COM_NULL_DACL = 0x0406
APPLICATION_VERIFIER_COM_UNSAFE_IMPERSONATION = 0x0407
APPLICATION_VERIFIER_COM_SMUGGLED_WRAPPER = 0x0408
APPLICATION_VERIFIER_COM_SMUGGLED_PROXY = 0x0409
APPLICATION_VERIFIER_COM_CF_SUCCESS_WITH_NULL = 0x040A
APPLICATION_VERIFIER_COM_GCO_SUCCESS_WITH_NULL = 0x040B
APPLICATION_VERIFIER_COM_OBJECT_IN_FREED_MEMORY = 0x040C
APPLICATION_VERIFIER_COM_OBJECT_IN_UNLOADED_DLL = 0x040D
APPLICATION_VERIFIER_COM_VTBL_IN_FREED_MEMORY = 0x040E
APPLICATION_VERIFIER_COM_VTBL_IN_UNLOADED_DLL = 0x040F
APPLICATION_VERIFIER_COM_HOLDING_LOCKS_ON_CALL = 0x0410

APPLICATION_VERIFIER_RPC_ERROR = 0x0500

APPLICATION_VERIFIER_INVALID_FREEMEM = 0x0600
APPLICATION_VERIFIER_INVALID_ALLOCMEM = 0x0601
APPLICATION_VERIFIER_INVALID_MAPVIEW = 0x0602
APPLICATION_VERIFIER_PROBE_INVALID_ADDRESS = 0x0603
APPLICATION_VERIFIER_PROBE_FREE_MEM = 0x0604
APPLICATION_VERIFIER_PROBE_GUARD_PAGE = 0x0605
APPLICATION_VERIFIER_PROBE_NULL = 0x0606
APPLICATION_VERIFIER_PROBE_INVALID_START_OR_SIZE = 0x0607
APPLICATION_VERIFIER_SIZE_HEAP_UNEXPECTED_EXCEPTION = 0x0618

RtlApplicationVerifierStop = NTAPI(VOID, 
                                   ULONG_PTR, 
                                   PSTR, 
                                   ULONG_PTR, 
                                   PSTR, 
                                   ULONG_PTR, 
                                   PSTR, 
                                   ULONG_PTR, 
                                   PSTR, 
                                   ULONG_PTR, 
                                   PSTR
)

RtlSetHeapInformation = NTAPI(DWORD, PVOID, UINT, PVOID, SIZE_T)
RtlQueryHeapInformation = NTAPI(DWORD, PVOID, UINT, PVOID, SIZE_T, PSIZE_T)
RtlMultipleAllocateHeap = NTAPI(DWORD, PVOID, DWORD, SIZE_T, DWORD, PVOID)
RtlMultipleFreeHeap = NTAPI(DWORD, PVOID, DWORD, DWORD, PVOID)


def VERIFIER_STOP(Code,Msg,P1,S1,P2,S2,P3,S3,P4,S4):
    return RtlApplicationVerifierStop(Code, 
                                      Msg, 
                                      ULONG_PTR(P1).value, 
                                      S1, 
                                      ULONG_PTR(P2).value, 
                                      S2,
                                      ULONG_PTR(P3).value, 
                                      S3, 
                                      ULONG_PTR(P4).value, 
                                      S4
    )

class _HARDWARE_COUNTER_DATA(Structure):
    _fields_ = [('Type', UINT),
                ('Reserved', DWORD),
                ('Value', DWORD64),
    ]

HARDWARE_COUNTER_DATA = _HARDWARE_COUNTER_DATA
PHARDWARE_COUNTER_DATA = POINTER(HARDWARE_COUNTER_DATA)

class _PERFORMANCE_DATA(Structure):
    _fields_ = [('Size', WORD),
                ('Version', BYTE),
                ('HwCountersCount', BYTE),
                ('ContextSwitchCount', DWORD),
                ('WaitReasonBitMap', DWORD64),
                ('CycleTime', DWORD64),
                ('RetryCount', DWORD),
                ('Reserved', DWORD),
                ('HwCounters', HARDWARE_COUNTER_DATA * MAX_HW_COUNTERS)
    ]

PERFORMANCE_DATA = _PERFORMANCE_DATA
PPERFORMANCE_DATA = POINTER(PERFORMANCE_DATA)

PERFORMANCE_DATA_VERSION = 1

READ_THREAD_PROFILING_FLAG_DISPATCHING = 0x00000001
READ_THREAD_PROFILING_FLAG_HARDWARE_COUNTERS = 0x00000002

DLL_PROCESS_ATTACH = 1
DLL_THREAD_ATTACH = 2
DLL_THREAD_DETACH = 3
DLL_PROCESS_DETACH = 0
DLL_PROCESS_VERIFIER = 4

EVENTLOG_SEQUENTIAL_READ = 0x0001
EVENTLOG_SEEK_READ = 0x0002
EVENTLOG_FORWARDS_READ = 0x0004
EVENTLOG_BACKWARDS_READ = 0x0008

EVENTLOG_SUCCESS = 0x0000
EVENTLOG_ERROR_TYPE = 0x0001
EVENTLOG_WARNING_TYPE = 0x0002
EVENTLOG_INFORMATION_TYPE = 0x0004
EVENTLOG_AUDIT_SUCCESS = 0x0008
EVENTLOG_AUDIT_FAILURE = 0x0010

EVENTLOG_START_PAIRED_EVENT = 0x0001
EVENTLOG_END_PAIRED_EVENT = 0x0002
EVENTLOG_END_ALL_PAIRED_EVENTS = 0x0004
EVENTLOG_PAIRED_EVENT_ACTIVE = 0x0008
EVENTLOG_PAIRED_EVENT_INACTIVE = 0x0010

class _EVENTLOGRECORD(Structure):
    _fields_ = [('Length', DWORD),
                ('Reserved', DWORD),
                ('RecordNumber', DWORD),
                ('TimeGenerated', DWORD),
                ('TimeWritten', DWORD),
                ('EventID', DWORD),
                ('EventType', WORD),
                ('NumStrings', WORD),
                ('EventCategory', WORD),
                ('ReservedFlags', WORD),
                ('ClosingRecordNumber', DWORD),
                ('StringOffset', DWORD),
                ('UserSidLength', DWORD),
                ('UserSidOffset', DWORD),
                ('DataLength', DWORD),
                ('DataOffset', DWORD)
    ]

EVENTLOGRECORD = _EVENTLOGRECORD
PEVENTLOGRECORD = POINTER(EVENTLOGRECORD)

MAXLOGICALLOGNAMESIZE = 256

class _EVENTSFORLOGFILE(Structure):
    _fields_ = [('ulSize', DWORD),
                ('szLogicalLogFile', WCHAR * MAXLOGICALLOGNAMESIZE),
                ('ulNumRecords', DWORD),
                ('pEventLogRecords', EVENTLOGRECORD),
    ]

EVENTSFORLOGFILE = _EVENTSFORLOGFILE
PEVENTSFORLOGFILE = POINTER(EVENTSFORLOGFILE)

class _PACKEDEVENTINFO(Structure):
    _fields_ = [('ulSize', DWORD),
                ('ulNumEventsForLogFile', DWORD),
                ('ulOffsets', DWORD),
    ]

PACKEDEVENTINFO = _PACKEDEVENTINFO
PPACKEDEVENTINFO = POINTER(PACKEDEVENTINFO)

KEY_QUERY_VALUE = 0x0001
KEY_SET_VALUE = 0x0002
KEY_CREATE_SUB_KEY = 0x0004
KEY_ENUMERATE_SUB_KEYS = 0x0008
KEY_NOTIFY = 0x0010
KEY_CREATE_LINK = 0x0020
KEY_WOW64_64KEY = 0x0100
KEY_WOW64_32KEY = 0x0200
KEY_WOW64_RES = 0x0300

KEY_READ = ((STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY) & (~SYNCHRONIZE))
KEY_WRITE = ((STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY) & (~SYNCHRONIZE))
KEY_EXECUTE = ((KEY_READ) & (~SYNCHRONIZE))
KEY_ALL_ACCESS = ((STANDARD_RIGHTS_ALL | 
                   KEY_QUERY_VALUE | 
                   KEY_SET_VALUE | 
                   KEY_CREATE_SUB_KEY | 
                   KEY_ENUMERATE_SUB_KEYS | 
                   KEY_NOTIFY | 
                   KEY_CREATE_LINK) & (~SYNCHRONIZE))

REG_OPTION_RESERVED = 0x00000000

REG_OPTION_NON_VOLATILE = 0x00000000
REG_OPTION_VOLATILE = 0x00000001
REG_OPTION_CREATE_LINK = 0x00000002
REG_OPTION_BACKUP_RESTORE = 0x00000004
REG_OPTION_OPEN_LINK = 0x00000008
REG_LEGAL_OPTION = (REG_OPTION_RESERVED | 
                    REG_OPTION_NON_VOLATILE | 
                    REG_OPTION_VOLATILE | 
                    REG_OPTION_CREATE_LINK | 
                    REG_OPTION_BACKUP_RESTORE | 
                    REG_OPTION_OPEN_LINK
)

REG_CREATED_NEW_KEY = 0x00000001
REG_OPENED_EXISTING_KEY = 0x00000002

REG_STANDARD_FORMAT = 1
REG_LATEST_FORMAT = 2
REG_NO_COMPRESSION = 4

REG_WHOLE_HIVE_VOLATILE = 0x00000001
REG_REFRESH_HIVE = 0x00000002
REG_NO_LAZY_FLUSH = 0x00000004
REG_FORCE_RESTORE = 0x00000008
REG_APP_HIVE = 0x00000010
REG_PROCESS_PRIVATE = 0x00000020
REG_START_JOURNAL = 0x00000040
REG_HIVE_EXACT_FILE_GROWTH = 0x00000080
REG_HIVE_NO_RM = 0x00000100
REG_HIVE_SINGLE_LOG = 0x00000200
REG_BOOT_HIVE = 0x00000400

REG_FORCE_UNLOAD = 1

REG_NOTIFY_CHANGE_NAME = 0x00000001
REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
REG_NOTIFY_CHANGE_SECURITY = 0x00000008
REG_NOTIFY_THREAD_AGNOSTIC = 0x10000000

REG_LEGAL_CHANGE_FILTER = (REG_NOTIFY_CHANGE_NAME | 
                           REG_NOTIFY_CHANGE_ATTRIBUTES | 
                           REG_NOTIFY_CHANGE_LAST_SET | 
                           REG_NOTIFY_CHANGE_SECURITY | 
                           REG_NOTIFY_THREAD_AGNOSTIC
)

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_LITTLE_ENDIAN = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_RESOURCE_LIST = 8
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD = 11
REG_QWORD_LITTLE_ENDIAN = 11

SERVICE_KERNEL_DRIVER = 0x00000001
SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
SERVICE_ADAPTER = 0x00000004
SERVICE_RECOGNIZER_DRIVER = 0x00000008

SERVICE_DRIVER = (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER)

SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_WIN32_SHARE_PROCESS = 0x00000020

SERVICE_WIN32 = (SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS)

SERVICE_INTERACTIVE_PROCESS = 0x00000100

SERVICE_TYPE_ALL = (SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS)

SERVICE_BOOT_START = 0x00000000
SERVICE_SYSTEM_START = 0x00000001
SERVICE_AUTO_START = 0x00000002
SERVICE_DEMAND_START = 0x00000003
SERVICE_DISABLED = 0x00000004

SERVICE_ERROR_IGNORE = 0x00000000
SERVICE_ERROR_NORMAL = 0x00000001
SERVICE_ERROR_SEVERE = 0x00000002
SERVICE_ERROR_CRITICAL = 0x00000003

DriverType = SERVICE_KERNEL_DRIVER
FileSystemType = SERVICE_FILE_SYSTEM_DRIVER
Win32ServiceOwnProcess = SERVICE_WIN32_OWN_PROCESS
Win32ServiceShareProcess = SERVICE_WIN32_SHARE_PROCESS
AdapterType = SERVICE_ADAPTER
RecognizerType = SERVICE_RECOGNIZER_DRIVER

class _CM_SERVICE_NODE_TYPE(enum.IntFlag):
    DriverType = SERVICE_KERNEL_DRIVER
    FileSystemType = SERVICE_FILE_SYSTEM_DRIVER
    Win32ServiceOwnProcess = SERVICE_WIN32_OWN_PROCESS
    Win32ServiceShareProcess = SERVICE_WIN32_SHARE_PROCESS
    AdapterType = SERVICE_ADAPTER
    RecognizerType = SERVICE_RECOGNIZER_DRIVER

CM_SERVICE_NODE_TYPE = _CM_SERVICE_NODE_TYPE

BootLoad = SERVICE_BOOT_START
SystemLoad = SERVICE_SYSTEM_START
AutoLoad = SERVICE_AUTO_START
DemandLoad = SERVICE_DEMAND_START
DisableLoad = SERVICE_DISABLED

class _CM_SERVICE_LOAD_TYPE(enum.IntFlag):
    BootLoad = SERVICE_BOOT_START
    SystemLoad = SERVICE_SYSTEM_START
    AutoLoad = SERVICE_AUTO_START
    DemandLoad = SERVICE_DEMAND_START
    DisableLoad = SERVICE_DISABLED

CM_SERVICE_LOAD_TYPE = _CM_SERVICE_LOAD_TYPE

IgnoreError = SERVICE_ERROR_IGNORE
NormalError = SERVICE_ERROR_NORMAL
SevereError = SERVICE_ERROR_SEVERE
CriticalError = SERVICE_ERROR_CRITICAL

class _CM_ERROR_CONTROL_TYPE(enum.IntFlag):
    IgnoreError = SERVICE_ERROR_IGNORE
    NormalError = SERVICE_ERROR_NORMAL
    SevereError = SERVICE_ERROR_SEVERE
    CriticalError = SERVICE_ERROR_CRITICAL

CM_ERROR_CONTROL_TYPE = _CM_ERROR_CONTROL_TYPE

CM_SERVICE_NETWORK_BOOT_LOAD = 0x00000001
CM_SERVICE_VIRTUAL_DISK_BOOT_LOAD = 0x00000002
CM_SERVICE_USB_DISK_BOOT_LOAD = 0x00000004
CM_SERVICE_SD_DISK_BOOT_LOAD = 0x00000008
CM_SERVICE_USB3_DISK_BOOT_LOAD = 0x00000010
CM_SERVICE_MEASURED_BOOT_LOAD = 0x00000020
CM_SERVICE_VERIFIER_BOOT_LOAD = 0x00000040
CM_SERVICE_WINPE_BOOT_LOAD = 0x00000080

CM_SERVICE_VALID_PROMOTION_MASK = (CM_SERVICE_NETWORK_BOOT_LOAD | 
                                   CM_SERVICE_VIRTUAL_DISK_BOOT_LOAD | 
                                   CM_SERVICE_USB_DISK_BOOT_LOAD | 
                                   CM_SERVICE_SD_DISK_BOOT_LOAD | 
                                   CM_SERVICE_USB3_DISK_BOOT_LOAD | 
                                   CM_SERVICE_MEASURED_BOOT_LOAD | 
                                   CM_SERVICE_VERIFIER_BOOT_LOAD | 
                                   CM_SERVICE_WINPE_BOOT_LOAD
)

TAPE_ERASE_SHORT = 0
TAPE_ERASE_LONG = 1

class _TAPE_ERASE(Structure):
    _fields_ = [('Type', DWORD),
                ('Immediate', BOOLEAN)
    ]

TAPE_ERASE = _TAPE_ERASE
PTAPE_ERASE = POINTER(TAPE_ERASE)

TAPE_LOAD = 0
TAPE_UNLOAD = 1
TAPE_TENSION = 2
TAPE_LOCK = 3
TAPE_UNLOCK = 4
TAPE_FORMAT = 5

class _TAPE_PREPARE(Structure):
    _fields_ = [('Operation', DWORD),
                ('Immediate', BOOLEAN)
    ]

TAPE_PREPARE = _TAPE_PREPARE
PTAPE_PREPARE = POINTER(TAPE_PREPARE)

TAPE_SETMARKS = 0
TAPE_FILEMARKS = 1
TAPE_SHORT_FILEMARKS = 2
TAPE_LONG_FILEMARKS = 3

class _TAPE_WRITE_MARKS(Structure):
    _fields_ = [('Type', DWORD),
                ('Count', DWORD),
                ('Immediate', BOOLEAN),
    ]

TAPE_WRITE_MARKS = _TAPE_WRITE_MARKS
PTAPE_WRITE_MARKS = POINTER(TAPE_WRITE_MARKS)

TAPE_ABSOLUTE_POSITION = 0
TAPE_LOGICAL_POSITION = 1
TAPE_PSEUDO_LOGICAL_POSITION = 2

class _TAPE_GET_POSITION(Structure):
    _fields_ = [('Type', DWORD),
                ('Partition', DWORD),
                ('Offset', LARGE_INTEGER),
    ]

TAPE_GET_POSITION = _TAPE_GET_POSITION
PTAPE_GET_POSITION = POINTER(TAPE_GET_POSITION)

TAPE_REWIND = 0
TAPE_ABSOLUTE_BLOCK = 1
TAPE_LOGICAL_BLOCK = 2
TAPE_PSEUDO_LOGICAL_BLOCK = 3
TAPE_SPACE_END_OF_DATA = 4
TAPE_SPACE_RELATIVE_BLOCKS = 5
TAPE_SPACE_FILEMARKS = 6
TAPE_SPACE_SEQUENTIAL_FMKS = 7
TAPE_SPACE_SETMARKS = 8
TAPE_SPACE_SEQUENTIAL_SMKS = 9

class _TAPE_SET_POSITION(Structure):
    _fields_ = [('Method', DWORD),
                ('Partition', DWORD),
                ('Offset', LARGE_INTEGER),
                ('Immediate', BOOLEAN),
    ]

TAPE_SET_POSITION = _TAPE_SET_POSITION
PTAPE_SET_POSITION = POINTER(TAPE_SET_POSITION)

TAPE_DRIVE_FIXED = 0x00000001
TAPE_DRIVE_SELECT = 0x00000002
TAPE_DRIVE_INITIATOR = 0x00000004

TAPE_DRIVE_ERASE_SHORT = 0x00000010
TAPE_DRIVE_ERASE_LONG = 0x00000020
TAPE_DRIVE_ERASE_BOP_ONLY = 0x00000040
TAPE_DRIVE_ERASE_IMMEDIATE = 0x00000080
TAPE_DRIVE_TAPE_CAPACITY = 0x00000100
TAPE_DRIVE_TAPE_REMAINING = 0x00000200
TAPE_DRIVE_FIXED_BLOCK = 0x00000400
TAPE_DRIVE_VARIABLE_BLOCK = 0x00000800
TAPE_DRIVE_WRITE_PROTECT = 0x00001000
TAPE_DRIVE_EOT_WZ_SIZE = 0x00002000
TAPE_DRIVE_ECC = 0x00010000
TAPE_DRIVE_COMPRESSION = 0x00020000
TAPE_DRIVE_PADDING = 0x00040000
TAPE_DRIVE_REPORT_SMKS = 0x00080000
TAPE_DRIVE_GET_ABSOLUTE_BLK = 0x00100000
TAPE_DRIVE_GET_LOGICAL_BLK = 0x00200000
TAPE_DRIVE_SET_EOT_WZ_SIZE = 0x00400000
TAPE_DRIVE_EJECT_MEDIA = 0x01000000
TAPE_DRIVE_CLEAN_REQUESTS = 0x02000000
TAPE_DRIVE_SET_CMP_BOP_ONLY = 0x04000000

TAPE_DRIVE_RESERVED_BIT = 0x80000000

TAPE_DRIVE_LOAD_UNLOAD = 0x80000001
TAPE_DRIVE_TENSION = 0x80000002
TAPE_DRIVE_LOCK_UNLOCK = 0x80000004
TAPE_DRIVE_REWIND_IMMEDIATE = 0x80000008
TAPE_DRIVE_SET_BLOCK_SIZE = 0x80000010

TAPE_DRIVE_LOAD_UNLD_IMMED = 0x80000020
TAPE_DRIVE_TENSION_IMMED = 0x80000040
TAPE_DRIVE_LOCK_UNLK_IMMED = 0x80000080

TAPE_DRIVE_SET_ECC = 0x80000100
TAPE_DRIVE_SET_COMPRESSION = 0x80000200
TAPE_DRIVE_SET_PADDING = 0x80000400
TAPE_DRIVE_SET_REPORT_SMKS = 0x80000800

TAPE_DRIVE_ABSOLUTE_BLK = 0x80001000
TAPE_DRIVE_ABS_BLK_IMMED = 0x80002000
TAPE_DRIVE_LOGICAL_BLK = 0x80004000
TAPE_DRIVE_LOG_BLK_IMMED = 0x80008000

TAPE_DRIVE_END_OF_DATA = 0x80010000
TAPE_DRIVE_RELATIVE_BLKS = 0x80020000
TAPE_DRIVE_FILEMARKS = 0x80040000
TAPE_DRIVE_SEQUENTIAL_FMKS = 0x80080000

TAPE_DRIVE_SETMARKS = 0x80100000
TAPE_DRIVE_SEQUENTIAL_SMKS = 0x80200000
TAPE_DRIVE_REVERSE_POSITION = 0x80400000
TAPE_DRIVE_SPACE_IMMEDIATE = 0x80800000

TAPE_DRIVE_WRITE_SETMARKS = 0x81000000
TAPE_DRIVE_WRITE_FILEMARKS = 0x82000000
TAPE_DRIVE_WRITE_SHORT_FMKS = 0x84000000
TAPE_DRIVE_WRITE_LONG_FMKS = 0x88000000

TAPE_DRIVE_WRITE_MARK_IMMED = 0x90000000
TAPE_DRIVE_FORMAT = 0xA0000000
TAPE_DRIVE_FORMAT_IMMEDIATE = 0xC0000000
TAPE_DRIVE_HIGH_FEATURES = 0x80000000

class _TAPE_GET_DRIVE_PARAMETERS(Structure):
    _fields_ = [('ECC', BOOLEAN), 
                ('Compression', BOOLEAN),
                ('DataPadding', BOOLEAN),
                ('ReportSetmarks', BOOLEAN),
                ('DefaultBlockSize', DWORD),
                ('MaximumBlockSize', DWORD),
                ('MinimumBlockSize', DWORD),
                ('MaximumPartitionCount', DWORD),
                ('FeaturesLow', DWORD),
                ('FeaturesHigh', DWORD),
                ('EOTWarningZoneSize', DWORD)
    ]

TAPE_GET_DRIVE_PARAMETERS = _TAPE_GET_DRIVE_PARAMETERS
PTAPE_GET_DRIVE_PARAMETERS = POINTER(TAPE_GET_DRIVE_PARAMETERS)

class _TAPE_SET_DRIVE_PARAMETERS(Structure):
    _fields_ = [('ECC', BOOLEAN),
                ('Compression', BOOLEAN),
                ('DataPadding', BOOLEAN),
                ('ReportSetmarks', BOOLEAN),
                ('EOTWarningZoneSize', DWORD)
    ]

TAPE_SET_DRIVE_PARAMETERS = _TAPE_SET_DRIVE_PARAMETERS
PTAPE_SET_DRIVE_PARAMETERS = POINTER(TAPE_SET_DRIVE_PARAMETERS)

class _TAPE_SET_MEDIA_PARAMETERS(Structure):
    _fields_ = [('BlockSize', DWORD)]

TAPE_SET_MEDIA_PARAMETERS = _TAPE_SET_MEDIA_PARAMETERS
PTAPE_SET_MEDIA_PARAMETERS = POINTER(TAPE_SET_MEDIA_PARAMETERS)

TAPE_FIXED_PARTITIONS = 0
TAPE_SELECT_PARTITIONS = 1
TAPE_INITIATOR_PARTITIONS = 2

class _TAPE_CREATE_PARTITION(Structure):
    _fields_ = [('Method', DWORD),
                ('Count', DWORD),
                ('Size', DWORD)
    ]

TAPE_CREATE_PARTITION = _TAPE_CREATE_PARTITION
PTAPE_CREATE_PARTITION = POINTER(TAPE_CREATE_PARTITION)

TAPE_QUERY_DRIVE_PARAMETERS = 0
TAPE_QUERY_MEDIA_CAPACITY = 1
TAPE_CHECK_FOR_DRIVE_PROBLEM = 2
TAPE_QUERY_IO_ERROR_DATA = 3
TAPE_QUERY_DEVICE_ERROR_DATA = 4

class _TAPE_WMI_OPERATIONS(Structure):
    _fields_ = [('Method', DWORD),
                ('DataBufferSize', DWORD),
                ('DataBuffer', PVOID)
    ]

TAPE_WMI_OPERATIONS = _TAPE_WMI_OPERATIONS
PTAPE_WMI_OPERATIONS = POINTER(TAPE_WMI_OPERATIONS)

TapeDriveProblemNone = 0
TapeDriveReadWriteWarning = 1
TapeDriveReadWriteError = 2
TapeDriveReadWarning = 3
TapeDriveWriteWarning = 4
TapeDriveReadError = 5
TapeDriveWriteError = 6
TapeDriveHardwareError = 7
TapeDriveUnsupportedMedia = 8
TapeDriveScsiConnectionError = 9
TapeDriveTimetoClean = 10
TapeDriveCleanDriveNow = 11
TapeDriveMediaLifeExpired = 12
TapeDriveSnappedTape = 13

class _TAPE_DRIVE_PROBLEM_TYPE(enum.IntFlag):
    TapeDriveProblemNone = 0
    TapeDriveReadWriteWarning = 1
    TapeDriveReadWriteError = 2
    TapeDriveReadWarning = 3
    TapeDriveWriteWarning = 4
    TapeDriveReadError = 5
    TapeDriveWriteError = 6
    TapeDriveHardwareError = 7
    TapeDriveUnsupportedMedia = 8
    TapeDriveScsiConnectionError = 9
    TapeDriveTimetoClean = 10
    TapeDriveCleanDriveNow = 11
    TapeDriveMediaLifeExpired = 12
    TapeDriveSnappedTape = 13

TAPE_DRIVE_PROBLEM_TYPE = _TAPE_DRIVE_PROBLEM_TYPE

TP_VERSION = DWORD
PTP_VERSION = PDWORD

class _TP_CALLBACK_INSTANCE(Structure):
    pass

TP_CALLBACK_INSTANCE = _TP_CALLBACK_INSTANCE
PTP_CALLBACK_INSTANCE  = POINTER(TP_CALLBACK_INSTANCE)

class _TP_CALLBACK_INSTANCE(Structure):
    pass

TP_CALLBACK_INSTANCE = _TP_CALLBACK_INSTANCE
PTP_CALLBACK_INSTANCE = POINTER(TP_CALLBACK_INSTANCE)

PTP_SIMPLE_CALLBACK = NTAPI(VOID, PTP_CALLBACK_INSTANCE, PVOID)

class _TP_POOL(Structure):
    pass

TP_POOL = _TP_POOL
PTP_POOL = POINTER(TP_POOL)

TP_CALLBACK_PRIORITY_HIGH = 0
TP_CALLBACK_PRIORITY_NORMAL = 1
TP_CALLBACK_PRIORITY_LOW = 2
TP_CALLBACK_PRIORITY_INVALID = 3
TP_CALLBACK_PRIORITY_COUNT = TP_CALLBACK_PRIORITY_INVALID

class _TP_CALLBACK_PRIORITY(enum.IntFlag):
    TP_CALLBACK_PRIORITY_HIGH = 0
    TP_CALLBACK_PRIORITY_NORMAL = 1
    TP_CALLBACK_PRIORITY_LOW = 2
    TP_CALLBACK_PRIORITY_INVALID = 3
    TP_CALLBACK_PRIORITY_COUNT = TP_CALLBACK_PRIORITY_INVALID

TP_CALLBACK_PRIORITY = _TP_CALLBACK_PRIORITY

class _TP_POOL_STACK_INFORMATION(Structure):
    _fields_ = [('StackReserve', SIZE_T),
                ('StackCommit', SIZE_T)
    ]

TP_POOL_STACK_INFORMATION = _TP_POOL_STACK_INFORMATION
PTP_POOL_STACK_INFORMATION = POINTER(TP_POOL_STACK_INFORMATION)

class _TP_CLEANUP_GROUP(Structure):
    pass

TP_CLEANUP_GROUP = _TP_CLEANUP_GROUP
PTP_CLEANUP_GROUP = POINTER(TP_CLEANUP_GROUP)

PTP_CLEANUP_GROUP_CANCEL_CALLBACK = NTAPI(VOID, PVOID, PVOID)

class _ACTIVATION_CONTEXT(Structure):
    pass

if WIN32_WINNT >= 0x0601:
    class _TP_CALLBACK_ENVIRON_V3(Structure):
        class u(Union):
            class s(LittleEndianStructure):
                _fields_ = [('LongFunction', DWORD, 1),
                            ('Persistent', DWORD, 1),
                            ('Private', DWORD, 30)
                ]
            
            _anonymous_ = ['s']
            _fields_ = [('Flags', DWORD),
                        ('s', s)
            ]
        
        _anonymous_ = ['u']
        _fields_ = [('Version', TP_VERSION),
                    ('Pool', PTP_POOL),
                    ('CleanupGroup', PTP_CLEANUP_GROUP),
                    ('CleanupGroupCancelCallback', PTP_CLEANUP_GROUP_CANCEL_CALLBACK),
                    ('RaceDll', PVOID),
                    ('ActivationContext', POINTER(_ACTIVATION_CONTEXT)),
                    ('FinalizationCallback', PTP_SIMPLE_CALLBACK),
                    ('u', u),
                    ('CallbackPriority', UINT),
                    ('Size', DWORD)
        ]

TP_CALLBACK_ENVIRON_V3 = _TP_CALLBACK_ENVIRON_V3
TP_CALLBACK_ENVIRON = TP_CALLBACK_ENVIRON_V3
PTP_CALLBACK_ENVIRON = POINTER(TP_CALLBACK_ENVIRON)

class _TP_WORK(Structure):
    pass

TP_WORK = _TP_WORK
PTP_WORK = POINTER(TP_WORK)

PTP_WORK_CALLBACK = NTAPI(VOID, PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK)

class _TP_TIMER(Structure):
    pass

TP_TIMER = _TP_TIMER
PTP_TIMER = POINTER(TP_TIMER)

PTP_TIMER_CALLBACK = NTAPI(VOID, PTP_CALLBACK_INSTANCE, PVOID, PTP_TIMER)

TP_WAIT_RESULT = DWORD

class _TP_WAIT(Structure):
    pass

TP_WAIT = _TP_WAIT
PTP_WAIT = POINTER(TP_WAIT)

PTP_WAIT_CALLBACK = NTAPI(VOID, PTP_CALLBACK_INSTANCE, PVOID, PTP_WAIT, TP_WAIT_RESULT)

class _TP_IO(Structure):
    pass

TP_IO = _TP_IO
PTP_IO = POINTER(TP_IO)

# ......

TRANSACTIONMANAGER_QUERY_INFORMATION = 0x00001
TRANSACTIONMANAGER_SET_INFORMATION = 0x00002
TRANSACTIONMANAGER_RECOVER = 0x00004
TRANSACTIONMANAGER_RENAME = 0x00008
TRANSACTIONMANAGER_CREATE_RM = 0x00010
TRANSACTIONMANAGER_BIND_TRANSACTION = 0x00020

TRANSACTIONMANAGER_GENERIC_READ = (STANDARD_RIGHTS_READ | TRANSACTIONMANAGER_QUERY_INFORMATION)
TRANSACTIONMANAGER_GENERIC_WRITE = (STANDARD_RIGHTS_WRITE | 
                                    TRANSACTIONMANAGER_SET_INFORMATION | 
                                    TRANSACTIONMANAGER_RECOVER | 
                                    TRANSACTIONMANAGER_RENAME | 
                                    TRANSACTIONMANAGER_CREATE_RM
)

TRANSACTIONMANAGER_GENERIC_EXECUTE = (STANDARD_RIGHTS_EXECUTE)
TRANSACTIONMANAGER_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                                 TRANSACTIONMANAGER_GENERIC_READ | 
                                 TRANSACTIONMANAGER_GENERIC_WRITE | 
                                 TRANSACTIONMANAGER_GENERIC_EXECUTE | 
                                 TRANSACTIONMANAGER_BIND_TRANSACTION
)

TRANSACTION_QUERY_INFORMATION = 0x0001
TRANSACTION_SET_INFORMATION = 0x0002
TRANSACTION_ENLIST = 0x0004
TRANSACTION_COMMIT = 0x0008
TRANSACTION_ROLLBACK = 0x0010
TRANSACTION_PROPAGATE = 0x0020
TRANSACTION_RIGHT_RESERVED1 = 0x0040

TRANSACTION_GENERIC_READ = (STANDARD_RIGHTS_READ | TRANSACTION_QUERY_INFORMATION | SYNCHRONIZE)
TRANSACTION_GENERIC_WRITE = (STANDARD_RIGHTS_WRITE | 
                             TRANSACTION_SET_INFORMATION | 
                             TRANSACTION_COMMIT | 
                             TRANSACTION_ENLIST | 
                             TRANSACTION_ROLLBACK | 
                             TRANSACTION_PROPAGATE | 
                             SYNCHRONIZE
)

TRANSACTION_GENERIC_EXECUTE = (STANDARD_RIGHTS_EXECUTE | TRANSACTION_COMMIT | TRANSACTION_ROLLBACK | SYNCHRONIZE)
TRANSACTION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TRANSACTION_GENERIC_READ | TRANSACTION_GENERIC_WRITE | TRANSACTION_GENERIC_EXECUTE)
TRANSACTION_RESOURCE_MANAGER_RIGHTS = (TRANSACTION_GENERIC_READ | 
                                       STANDARD_RIGHTS_WRITE | 
                                       TRANSACTION_SET_INFORMATION | 
                                       TRANSACTION_ENLIST | 
                                       TRANSACTION_ROLLBACK | 
                                       TRANSACTION_PROPAGATE | 
                                       SYNCHRONIZE
)

RESOURCEMANAGER_QUERY_INFORMATION = 0x0001
RESOURCEMANAGER_SET_INFORMATION = 0x0002
RESOURCEMANAGER_RECOVER = 0x0004
RESOURCEMANAGER_ENLIST = 0x0008
RESOURCEMANAGER_GET_NOTIFICATION = 0x0010
RESOURCEMANAGER_REGISTER_PROTOCOL = 0x0020
RESOURCEMANAGER_COMPLETE_PROPAGATION = 0x0040

RESOURCEMANAGER_GENERIC_READ = (STANDARD_RIGHTS_READ | RESOURCEMANAGER_QUERY_INFORMATION | SYNCHRONIZE)
RESOURCEMANAGER_GENERIC_WRITE = (STANDARD_RIGHTS_WRITE | 
                                 RESOURCEMANAGER_SET_INFORMATION | 
                                 RESOURCEMANAGER_RECOVER | 
                                 RESOURCEMANAGER_ENLIST | 
                                 RESOURCEMANAGER_GET_NOTIFICATION | 
                                 RESOURCEMANAGER_REGISTER_PROTOCOL | 
                                 RESOURCEMANAGER_COMPLETE_PROPAGATION | 
                                 SYNCHRONIZE
)

RESOURCEMANAGER_GENERIC_EXECUTE = (STANDARD_RIGHTS_EXECUTE | 
                                   RESOURCEMANAGER_RECOVER | 
                                   RESOURCEMANAGER_ENLIST | 
                                   RESOURCEMANAGER_GET_NOTIFICATION | 
                                   RESOURCEMANAGER_COMPLETE_PROPAGATION | 
                                   SYNCHRONIZE
)

RESOURCEMANAGER_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                              RESOURCEMANAGER_GENERIC_READ | 
                              RESOURCEMANAGER_GENERIC_WRITE | 
                              RESOURCEMANAGER_GENERIC_EXECUTE
)

ENLISTMENT_QUERY_INFORMATION = 1
ENLISTMENT_SET_INFORMATION = 2
ENLISTMENT_RECOVER = 4
ENLISTMENT_SUBORDINATE_RIGHTS = 8
ENLISTMENT_SUPERIOR_RIGHTS = 0x10

ENLISTMENT_GENERIC_READ = (STANDARD_RIGHTS_READ | ENLISTMENT_QUERY_INFORMATION)
ENLISTMENT_GENERIC_WRITE = (STANDARD_RIGHTS_WRITE | 
                            ENLISTMENT_SET_INFORMATION | 
                            ENLISTMENT_RECOVER | 
                            ENLISTMENT_SUBORDINATE_RIGHTS | 
                            ENLISTMENT_SUPERIOR_RIGHTS
)

ENLISTMENT_GENERIC_EXECUTE = (STANDARD_RIGHTS_EXECUTE | 
                              ENLISTMENT_RECOVER | 
                              ENLISTMENT_SUBORDINATE_RIGHTS | 
                              ENLISTMENT_SUPERIOR_RIGHTS
)

ENLISTMENT_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
                         ENLISTMENT_GENERIC_READ | 
                         ENLISTMENT_GENERIC_WRITE | 
                         ENLISTMENT_GENERIC_EXECUTE
)

TransactionOutcomeUndetermined = 1
TransactionOutcomeCommitted = 2
TransactionOutcomeAborted = 3

class _TRANSACTION_OUTCOME(enum.IntFlag):
    TransactionOutcomeUndetermined = 1
    TransactionOutcomeCommitted = 2
    TransactionOutcomeAborted = 3

TRANSACTION_OUTCOME = _TRANSACTION_OUTCOME

TransactionStateNormal = 1
TransactionStateIndoubt = 2
TransactionStateCommittedNotify = 3

class _TRANSACTION_STATE(enum.IntFlag):
    TransactionStateNormal = 1
    TransactionStateIndoubt = 2
    TransactionStateCommittedNotify = 3

TRANSACTION_STATE = _TRANSACTION_STATE

class _TRANSACTION_BASIC_INFORMATION(Structure):
    _fields_ = [('TransactionId', GUID),
                ('State', DWORD),
                ('Outcome', DWORD)
    ]

TRANSACTION_BASIC_INFORMATION = _TRANSACTION_BASIC_INFORMATION
PTRANSACTION_BASIC_INFORMATION = POINTER(TRANSACTION_BASIC_INFORMATION)

class _TRANSACTIONMANAGER_BASIC_INFORMATION(Structure):
    _fields_ = [('TmIdentity', GUID),
                ('VirtualClock', LARGE_INTEGER)
    ]

TRANSACTIONMANAGER_BASIC_INFORMATION = _TRANSACTIONMANAGER_BASIC_INFORMATION
PTRANSACTIONMANAGER_BASIC_INFORMATION = POINTER(TRANSACTIONMANAGER_BASIC_INFORMATION)

class _TRANSACTIONMANAGER_LOG_INFORMATION(Structure):
    _fields_ = [('LogIdentity', GUID)]

TRANSACTIONMANAGER_LOG_INFORMATION = _TRANSACTIONMANAGER_LOG_INFORMATION
PTRANSACTIONMANAGER_LOG_INFORMATION = POINTER(TRANSACTIONMANAGER_LOG_INFORMATION)

class _TRANSACTIONMANAGER_LOGPATH_INFORMATION(Structure):
    _fields_ = [('LogPathLength', DWORD),
                ('LogPath', WCHAR * 1)
    ]

TRANSACTIONMANAGER_LOGPATH_INFORMATION = _TRANSACTIONMANAGER_LOGPATH_INFORMATION
PTRANSACTIONMANAGER_LOGPATH_INFORMATION = POINTER(TRANSACTIONMANAGER_LOGPATH_INFORMATION)

class _TRANSACTIONMANAGER_RECOVERY_INFORMATION(Structure):
    _fields_ = [('LastRecoveredLsn', ULONGLONG)]

TRANSACTIONMANAGER_RECOVERY_INFORMATION = _TRANSACTIONMANAGER_RECOVERY_INFORMATION
PTRANSACTIONMANAGER_RECOVERY_INFORMATION = POINTER(TRANSACTIONMANAGER_RECOVERY_INFORMATION)

class _TRANSACTIONMANAGER_OLDEST_INFORMATION(Structure):
    _fields_ = [('OldestTransactionGuid', GUID)]

TRANSACTIONMANAGER_OLDEST_INFORMATION = _TRANSACTIONMANAGER_OLDEST_INFORMATION
PTRANSACTIONMANAGER_OLDEST_INFORMATION = POINTER(TRANSACTIONMANAGER_OLDEST_INFORMATION)

class _TRANSACTION_PROPERTIES_INFORMATION(Structure):
    _fields_ = [('IsolationLevel', DWORD),
                ('IsolationFlags', DWORD),
                ('Timeout', LARGE_INTEGER),
                ('Outcome', DWORD),
                ('DescriptionLength', DWORD),
                ('Description', WCHAR * 1),
    ]

TRANSACTION_PROPERTIES_INFORMATION = _TRANSACTION_PROPERTIES_INFORMATION
PTRANSACTION_PROPERTIES_INFORMATION = POINTER(TRANSACTION_PROPERTIES_INFORMATION)

class _TRANSACTION_BIND_INFORMATION(Structure):
    _fields_ = [('TmHandle', HANDLE)]

TRANSACTION_BIND_INFORMATION = _TRANSACTION_BIND_INFORMATION
PTRANSACTION_BIND_INFORMATION = POINTER(TRANSACTION_BIND_INFORMATION)

class _TRANSACTION_ENLISTMENT_PAIR(Structure):
    _fields_ = [('EnlistmentId', GUID),
                ('ResourceManagerId', GUID)
    ]

TRANSACTION_ENLISTMENT_PAIR = _TRANSACTION_ENLISTMENT_PAIR
PTRANSACTION_ENLISTMENT_PAIR = POINTER(TRANSACTION_ENLISTMENT_PAIR)

class _TRANSACTION_ENLISTMENTS_INFORMATION(Structure):
    _fields_ = [('NumberOfEnlistments', DWORD),
                ('EnlistmentPair', TRANSACTION_ENLISTMENT_PAIR * 1)
    ]

TRANSACTION_ENLISTMENTS_INFORMATION = _TRANSACTION_ENLISTMENTS_INFORMATION
PTRANSACTION_ENLISTMENTS_INFORMATION = POINTER(TRANSACTION_ENLISTMENTS_INFORMATION)

class _TRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION(Structure):
    _fields_ = [('SuperiorEnlistmentPair', TRANSACTION_ENLISTMENT_PAIR)]

TRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION = _TRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION
PTRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION = POINTER(TRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION)

class _RESOURCEMANAGER_BASIC_INFORMATION(Structure):
    _fields_ = [('ResourceManagerId', GUID),
                ('DescriptionLength', DWORD),
                ('Description', WCHAR * 1)
    ]

RESOURCEMANAGER_BASIC_INFORMATION = _RESOURCEMANAGER_BASIC_INFORMATION
PRESOURCEMANAGER_BASIC_INFORMATION = POINTER(RESOURCEMANAGER_BASIC_INFORMATION)

class _RESOURCEMANAGER_COMPLETION_INFORMATION(Structure):
    _fields_ = [('IoCompletionPortHandle', HANDLE),
                ('CompletionKey', ULONG_PTR)
    ]

RESOURCEMANAGER_COMPLETION_INFORMATION = _RESOURCEMANAGER_COMPLETION_INFORMATION
PRESOURCEMANAGER_COMPLETION_INFORMATION = POINTER(RESOURCEMANAGER_COMPLETION_INFORMATION)

TransactionBasicInformation = 0
TransactionPropertiesInformation = 1
TransactionEnlistmentInformation = 2
TransactionSuperiorEnlistmentInformation = 3
TransactionBindInformation = 4
TransactionDTCPrivateInformation = 5

class _TRANSACTION_INFORMATION_CLASS(enum.IntFlag):
    TransactionBasicInformation = 0
    TransactionPropertiesInformation = 1
    TransactionEnlistmentInformation = 2
    TransactionSuperiorEnlistmentInformation = 3
    TransactionBindInformation = 4
    TransactionDTCPrivateInformation = 5

TRANSACTION_INFORMATION_CLASS = _TRANSACTION_INFORMATION_CLASS

TransactionManagerBasicInformation = 0
TransactionManagerLogInformation = 1
TransactionManagerLogPathInformation = 2
TransactionManagerOnlineProbeInformation = 3,
TransactionManagerRecoveryInformation = 4,
TransactionManagerOldestTransactionInformation = 5

class _TRANSACTIONMANAGER_INFORMATION_CLASS(enum.IntFlag):
    TransactionManagerBasicInformation = 0
    TransactionManagerLogInformation = 1
    TransactionManagerLogPathInformation = 2
    TransactionManagerOnlineProbeInformation = 3,
    TransactionManagerRecoveryInformation = 4,
    TransactionManagerOldestTransactionInformation = 5

TRANSACTIONMANAGER_INFORMATION_CLASS = _TRANSACTIONMANAGER_INFORMATION_CLASS

ResourceManagerBasicInformation = 0
ResourceManagerCompletionInformation = 1

class _RESOURCEMANAGER_INFORMATION_CLASS(enum.IntFlag):
    ResourceManagerBasicInformation = 0
    ResourceManagerCompletionInformation = 1

RESOURCEMANAGER_INFORMATION_CLASS = _RESOURCEMANAGER_INFORMATION_CLASS

class _ENLISTMENT_BASIC_INFORMATION(Structure):
    _fields_ = [('EnlistmentId', GUID),
                ('TransactionId', GUID),
                ('ResourceManagerId', GUID)
    ]

ENLISTMENT_BASIC_INFORMATION = _ENLISTMENT_BASIC_INFORMATION
PENLISTMENT_BASIC_INFORMATION = POINTER(ENLISTMENT_BASIC_INFORMATION)

class _ENLISTMENT_CRM_INFORMATION(Structure):
    _fields_ = [('CrmTransactionManagerId', GUID),
                ('CrmResourceManagerId', GUID),
                ('CrmEnlistmentId', GUID)
    ]

ENLISTMENT_CRM_INFORMATION = _ENLISTMENT_CRM_INFORMATION
PENLISTMENT_CRM_INFORMATION = POINTER(ENLISTMENT_CRM_INFORMATION)

EnlistmentBasicInformation = 0
EnlistmentRecoveryInformation = 1
EnlistmentCrmInformation = 2

class _ENLISTMENT_INFORMATION_CLASS(enum.IntFlag):
    EnlistmentBasicInformation = 0
    EnlistmentRecoveryInformation = 1
    EnlistmentCrmInformation = 2

ENLISTMENT_INFORMATION_CLASS = _ENLISTMENT_INFORMATION_CLASS

class _TRANSACTION_LIST_ENTRY(Structure):
    _fields_ = [('UOW', GUID)]

TRANSACTION_LIST_ENTRY = _TRANSACTION_LIST_ENTRY
PTRANSACTION_LIST_ENTRY = POINTER(TRANSACTION_LIST_ENTRY)

class _TRANSACTION_LIST_INFORMATION(Structure):
    _fields_ = [('NumberOfTransactions', DWORD),
                ('TransactionInformation', TRANSACTION_LIST_ENTRY * 1)
    ]

TRANSACTION_LIST_INFORMATION = _TRANSACTION_LIST_INFORMATION
PTRANSACTION_LIST_INFORMATION = POINTER(TRANSACTION_LIST_INFORMATION)

KTMOBJECT_TRANSACTION = 0
KTMOBJECT_TRANSACTION_MANAGER = 1
KTMOBJECT_RESOURCE_MANAGER = 2
KTMOBJECT_ENLISTMENT = 3
KTMOBJECT_INVALID = 4

class _KTMOBJECT_TYPE(enum.IntFlag):
    KTMOBJECT_TRANSACTION = 0
    KTMOBJECT_TRANSACTION_MANAGER = 1
    KTMOBJECT_RESOURCE_MANAGER = 2
    KTMOBJECT_ENLISTMENT = 3
    KTMOBJECT_INVALID = 4

KTMOBJECT_TYPE = _KTMOBJECT_TYPE
PKTMOBJECT_TYPE = KTMOBJECT_TYPE

class _KTMOBJECT_CURSOR(Structure):
    _fields_ = [('LastQuery', GUID),
                ('ObjectIdCount', DWORD),
                ('ObjectIds', GUID * 1)
    ]

KTMOBJECT_CURSOR = _KTMOBJECT_CURSOR
PKTMOBJECT_CURSOR = POINTER(KTMOBJECT_CURSOR)

WOW64_CONTEXT_i386 = 0x00010000
WOW64_CONTEXT_i486 = 0x00010000
WOW64_CONTEXT_CONTROL = (WOW64_CONTEXT_i386 | 0x00000001)
WOW64_CONTEXT_INTEGER = (WOW64_CONTEXT_i386 | 0x00000002)
WOW64_CONTEXT_SEGMENTS = (WOW64_CONTEXT_i386 | 0x00000004)
WOW64_CONTEXT_FLOATING_POINT = (WOW64_CONTEXT_i386 | 0x00000008)
WOW64_CONTEXT_DEBUG_REGISTERS = (WOW64_CONTEXT_i386 | 0x00000010)
WOW64_CONTEXT_EXTENDED_REGISTERS = (WOW64_CONTEXT_i386 | 0x00000020)
WOW64_CONTEXT_FULL = (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS)
WOW64_CONTEXT_ALL = (WOW64_CONTEXT_CONTROL | 
                     WOW64_CONTEXT_INTEGER | 
                     WOW64_CONTEXT_SEGMENTS | 
                     WOW64_CONTEXT_FLOATING_POINT | 
                     WOW64_CONTEXT_DEBUG_REGISTERS | 
                     WOW64_CONTEXT_EXTENDED_REGISTERS
)

WOW64_CONTEXT_XSTATE = (WOW64_CONTEXT_i386 | 0x00000040)

WOW64_CONTEXT_EXCEPTION_ACTIVE = 0x08000000
WOW64_CONTEXT_SERVICE_ACTIVE = 0x10000000
WOW64_CONTEXT_EXCEPTION_REQUEST = 0x40000000
WOW64_CONTEXT_EXCEPTION_REPORTING = 0x80000000

WOW64_SIZE_OF_80387_REGISTERS = 80
WOW64_MAXIMUM_SUPPORTED_EXTENSION = 512

class _WOW64_FLOATING_SAVE_AREA(Structure):
    _fields_ = [('ControlWord', DWORD),
                ('StatusWord', DWORD),
                ('TagWord', DWORD),
                ('ErrorOffset', DWORD),
                ('ErrorSelector', DWORD),
                ('DataOffset', DWORD),
                ('DataSelector', DWORD),
                ('RegisterArea', BYTE * WOW64_SIZE_OF_80387_REGISTERS),
                ('Cr0NpxState', DWORD)
    ]

WOW64_FLOATING_SAVE_AREA = _WOW64_FLOATING_SAVE_AREA
PWOW64_FLOATING_SAVE_AREA = POINTER(WOW64_FLOATING_SAVE_AREA)

class _WOW64_CONTEXT(Structure):
    _fields_ = [
        ('ContextFlags', DWORD),
        ('Dr0', DWORD),
        ('Dr1', DWORD),
        ('Dr2', DWORD),
        ('Dr3', DWORD),
        ('Dr6', DWORD),
        ('Dr7', DWORD),
        ('FloatSave', WOW64_FLOATING_SAVE_AREA),
        ('SegGs', DWORD),
        ('SegFs', DWORD),
        ('SegEs', DWORD),
        ('SegDs', DWORD),
        ('Edi', DWORD),
        ('Esi', DWORD),
        ('Ebx', DWORD),
        ('Edx', DWORD),
        ('Ecx', DWORD),
        ('Eax', DWORD),
        ('Ebp', DWORD),
        ('Eip', DWORD),
        ('SegCs', DWORD),
        ('EFlags', DWORD),
        ('Esp', DWORD),
        ('SegSs', DWORD),
        ('ExtendedRegisters', BYTE * WOW64_MAXIMUM_SUPPORTED_EXTENSION)
    ]

WOW64_CONTEXT = _WOW64_CONTEXT
PWOW64_CONTEXT = POINTER(WOW64_CONTEXT)

class _WOW64_LDT_ENTRY(Structure):
    class HighWord(Union):
        class Bytes(Structure):
            _fields_ = [('BaseMid', BYTE),
                        ('Flags1', BYTE),
                        ('Flags2', BYTE),
                        ('BaseHi', BYTE)
            ]
        
        class Bits(Structure):
            _fields_ = [
                ('BaseMid', DWORD, 8),
                ('Type', DWORD, 5),
                ('Dpl', DWORD, 2),
                ('Pres', DWORD, 1),
                ('LimitHi', DWORD, 4),
                ('Sys', DWORD, 1),
                ('Reserved_0', DWORD, 1),
                ('Default_Big', DWORD, 1),
                ('Granularity', DWORD, 1),
                ('BaseHi', DWORD, 8)
            ]
        
        _anonymous_ = ['Bytes', 'Bits']
        _fields_ = [
            ('Bytes', Bytes),
            ('Bits', Bits)
        ]
    
    _anonymous_ = ['HighWord']
    _fields_ = [
        ('LimitLow', WORD),
        ('BaseLow', WORD),
        ('HighWord', HighWord),
    ]

WOW64_LDT_ENTRY = _WOW64_LDT_ENTRY
PWOW64_LDT_ENTRY = POINTER(WOW64_LDT_ENTRY)

class _WOW64_DESCRIPTOR_TABLE_ENTRY(Structure):
    _fields_ = [('Selector', DWORD),
                ('Descriptor', WOW64_LDT_ENTRY)
    ]

WOW64_DESCRIPTOR_TABLE_ENTRY = _WOW64_DESCRIPTOR_TABLE_ENTRY
PWOW64_DESCRIPTOR_TABLE_ENTRY = POINTER(WOW64_DESCRIPTOR_TABLE_ENTRY)

if WIN32_WINNT >= 0x0601:
    class _PROCESSOR_NUMBER(Structure):
        _fields_ = [('Group', WORD),
                    ('Number', BYTE),
                    ('Reserved', BYTE)
        ]
    
    PROCESSOR_NUMBER = _PROCESSOR_NUMBER
    PPROCESSOR_NUMBER = POINTER(PROCESSOR_NUMBER)

ALL_PROCESSOR_GROUPS = 0xffff

ACTIVATION_CONTEXT_SECTION_ASSEMBLY_INFORMATION = 1
ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION = 2
ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION = 3
ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION = 4
ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION = 5
ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION = 6
ACTIVATION_CONTEXT_SECTION_COM_PROGID_REDIRECTION = 7
ACTIVATION_CONTEXT_SECTION_GLOBAL_OBJECT_RENAME_TABLE = 8
ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES = 9
ACTIVATION_CONTEXT_SECTION_APPLICATION_SETTINGS = 10
ACTIVATION_CONTEXT_SECTION_COMPATIBILITY_INFO = 11
ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES = 12
