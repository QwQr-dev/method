# coding = 'utf-8'
# apiset.h

from method.System.winusutypes import *
from method.System.public_dll import ntdll
from method.System.errcheck import ntstatus_to_errcheck

NTAPI = WINFUNCTYPE
PCUNICODE_STRING = PUNICODE_STRING

API_SET_PREFIX_NAME_A = b"API-"
API_SET_PREFIX_NAME_U = "API-"

API_SET_EXTENSION_NAME_A = b"EXT-"
API_SET_EXTENSION_NAME_U = "EXT-"

# API_SET_SCHEMA_NAME = ApiSetSchema
API_SET_SECTION_NAME =  b".apiset"
API_SET_SCHEMA_SUFFIX = ".sys"

API_SET_SCHEMA_VERSION = 2

API_SET_LOAD_SCHEMA_ORDINAL = 1
API_SET_LOOKUP_ORDINAL = 2
API_SET_RELEASE_SCHEMA_ORDINAL = 3

class _API_SET_VALUE_ENTRY(Structure):
    _fields_ = [
        ('NameOffset', ULONG),
        ('NameLength', ULONG),
        ('ValueOffset', ULONG),
        ('ValueLength', ULONG)
    ]

API_SET_VALUE_ENTRY = _API_SET_VALUE_ENTRY
PAPI_SET_VALUE_ENTRY = POINTER(API_SET_VALUE_ENTRY)

PCAPI_SET_VALUE_ENTRY = PAPI_SET_VALUE_ENTRY

class _API_SET_VALUE_ARRAY(Structure):
    _fields_ = [
        ('Count', ULONG),
        ('Array', API_SET_VALUE_ENTRY * 1)
    ]

API_SET_VALUE_ARRAY = _API_SET_VALUE_ARRAY
PAPI_SET_VALUE_ARRAY = POINTER(API_SET_VALUE_ARRAY)

PCAPI_SET_VALUE_ARRAY = PAPI_SET_VALUE_ARRAY

class _API_SET_NAMESPACE_ENTRY(Structure):
    _fields_ = [
        ('NameOffset', ULONG),
        ('NameLength', ULONG),
        ('DataOffset', ULONG)
    ]

API_SET_NAMESPACE_ENTRY = _API_SET_NAMESPACE_ENTRY
PAPI_SET_NAMESPACE_ENTRY = POINTER(API_SET_NAMESPACE_ENTRY)

PCAPI_SET_NAMESPACE_ENTRY = PAPI_SET_NAMESPACE_ENTRY

class _API_SET_NAMESPACE_ARRAY(Structure):
    _fields_ = [
        ('Version', ULONG),
        ('Count', ULONG),
        ('Array', API_SET_NAMESPACE_ENTRY * 1)
    ]

API_SET_NAMESPACE_ARRAY = _API_SET_NAMESPACE_ARRAY
PAPI_SET_NAMESPACE_ARRAY = POINTER(API_SET_NAMESPACE_ARRAY)

PCAPI_SET_NAMESPACE_ARRAY = PAPI_SET_NAMESPACE_ARRAY

PAPI_SET_LOAD_SCHEMA_RTN = NTAPI(NTSTATUS, PCSTR, PCAPI_SET_NAMESPACE_ARRAY, PVOID)
PAPI_SET_LOOKUP_HELPER_RTN = NTAPI(NTSTATUS, PCAPI_SET_NAMESPACE_ARRAY, PCSTR, PCSTR, PBOOLEAN, PSTR, ULONG)
PAPI_SET_RELEASE_SCHEMA_RTN = NTAPI(NTSTATUS, PVOID)


def ApiSetResolveToHost(
    ApiSetSchema,
    FileNameIn,
    ParentName,
    Resolved,
    HostBinary,
    errcheck: bool = True
):
    
    ApiSetResolveToHost = ntdll.ApiSetResolveToHost
    ApiSetResolveToHost.argtypes = [
        PCAPI_SET_NAMESPACE_ARRAY,
        PCUNICODE_STRING,
        PCUNICODE_STRING,
        PBOOLEAN,
        PCUNICODE_STRING
    ]

    ApiSetResolveToHost.restype = NTSTATUS
    res = ApiSetResolveToHost(
        ApiSetSchema,
        FileNameIn,
        ParentName,
        Resolved,
        HostBinary
    )

    return ntstatus_to_errcheck(res, errcheck)
