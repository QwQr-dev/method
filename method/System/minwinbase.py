# coding = 'utf-8'
# minwinbase.h

from method.System.winnt import *
from method.System.public_dll import *
from method.System.winusutypes import *

MoveMemory = RtlMoveMemory
CopyMemory = RtlCopyMemory
FillMemory = RtlFillMemory
ZeroMemory = RtlZeroMemory

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength', DWORD),
        ('lpSecurityDescriptor', LPVOID),
        ('bInheritHandle', WINBOOL)
    ]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
PSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)
LPSECURITY_ATTRIBUTES = PSECURITY_ATTRIBUTES

class _OVERLAPPED(Structure):
    class DUMMYUNIONNAME(Union):
        class DUMMYSTRUCTNAME(Structure):
            _fields_ = [
                ('Offset', DWORD),
                ('OffsetHigh', DWORD)
            ]
        
        _anonymous_ = ['DUMMYSTRUCTNAME']
        _fields_ = [
            ('DUMMYSTRUCTNAME', DUMMYSTRUCTNAME),
            ('Pointer', PVOID)
        ]
    
    _anonymous_ = ['DUMMYUNIONNAME']
    _fields_ = [
        ('Internal', ULONG_PTR),
        ('InternalHigh', ULONG_PTR),
        ('DUMMYUNIONNAME', DUMMYUNIONNAME),
        ('hEvent', HANDLE)
    ]

OVERLAPPED = _OVERLAPPED
LPOVERLAPPED = POINTER(OVERLAPPED)

class _OVERLAPPED_ENTRY(Structure):
    _fields_ = [
        ('lpCompletionKey', ULONG_PTR),
        ('lpOverlapped', LPOVERLAPPED),
        ('Internal', ULONG_PTR),
        ('dwNumberOfBytesTransferred', DWORD)
    ]

OVERLAPPED_ENTRY = _OVERLAPPED_ENTRY
LPOVERLAPPED_ENTRY = POINTER(OVERLAPPED_ENTRY)

class _FILETIME(Structure):
    _fields_ = [
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', DWORD)
    ]

FILETIME = _FILETIME
PFILETIME = POINTER(FILETIME)
LPFILETIME = PFILETIME

class _SYSTEMTIME(Structure):
    _fields_ = [
        ('wYear', WORD),
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

class _WIN32_FIND_DATAA(Structure):
    _fields_ = [
        ('dwFileAttributes', DWORD),
        ('ftCreationTime', FILETIME),
        ('ftLastAccessTime', FILETIME),
        ('ftLastWriteTime', FILETIME),
        ('nFileSizeHigh', DWORD),
        ('nFileSizeLow', DWORD),
        ('dwReserved0', DWORD),
        ('dwReserved1', DWORD),
        ('cFileName', CHAR * MAX_PATH),
        ('cAlternateFileName', CHAR * 14)
    ]

WIN32_FIND_DATAA = _WIN32_FIND_DATAA
PWIN32_FIND_DATAA = POINTER(WIN32_FIND_DATAA)
LPWIN32_FIND_DATAA = PWIN32_FIND_DATAA

class _WIN32_FIND_DATAW(Structure):
    _fields_ = [
        ('dwFileAttributes', DWORD),
        ('ftCreationTime', FILETIME),
        ('ftLastAccessTime', FILETIME),
        ('ftLastWriteTime', FILETIME),
        ('nFileSizeHigh', DWORD),
        ('nFileSizeLow', DWORD),
        ('dwReserved0', DWORD),
        ('dwReserved1', DWORD),
        ('cFileName', WCHAR * MAX_PATH),
        ('cAlternateFileName', WCHAR * 14)
    ]

WIN32_FIND_DATAW = _WIN32_FIND_DATAW
PWIN32_FIND_DATAW = POINTER(WIN32_FIND_DATAW)
LPWIN32_FIND_DATAW = PWIN32_FIND_DATAW

WIN32_FIND_DATA = WIN32_FIND_DATAW if UNICODE else WIN32_FIND_DATAA
PWIN32_FIND_DATA = PWIN32_FIND_DATAW if UNICODE else PWIN32_FIND_DATAA
LPWIN32_FIND_DATA = LPWIN32_FIND_DATAW if UNICODE else LPWIN32_FIND_DATAA

FindExInfoStandard = 0
FindExInfoBasic = 1
FindExInfoMaxInfoLevel = 2

class _FINDEX_INFO_LEVELS(enum.Enum):
    FindExInfoStandard = 0
    FindExInfoBasic = 1
    FindExInfoMaxInfoLevel = 2

FINDEX_INFO_LEVELS = _FINDEX_INFO_LEVELS

FIND_FIRST_EX_CASE_SENSITIVE = 0x00000001
FIND_FIRST_EX_LARGE_FETCH = 0x00000002
FIND_FIRST_EX_ON_DISK_ENTRIES_ONLY =  0x00000004

CRITICAL_SECTION = RTL_CRITICAL_SECTION
PCRITICAL_SECTION = PRTL_CRITICAL_SECTION
LPCRITICAL_SECTION = PRTL_CRITICAL_SECTION
CRITICAL_SECTION_DEBUG = RTL_CRITICAL_SECTION_DEBUG
PCRITICAL_SECTION_DEBUG = PRTL_CRITICAL_SECTION_DEBUG
LPCRITICAL_SECTION_DEBUG = PRTL_CRITICAL_SECTION_DEBUG

LPOVERLAPPED_COMPLETION_ROUTINE = POINTER(WINAPI(VOID, DWORD, DWORD, LPOVERLAPPED))

LOCKFILE_FAIL_IMMEDIATELY = 0x1
LOCKFILE_EXCLUSIVE_LOCK = 0x2

class _PROCESS_HEAP_ENTRY(Structure):
    class DUMMYUNIONNAME(Union):
        class Block(Structure):
            _fields_ = [
                ('hMem', HANDLE),
                ('dwReserved', DWORD * 3)
            ]

        class Region(Structure):
            _fields_ = [
                ('dwCommittedSize', DWORD),
                ('dwUnCommittedSize', DWORD),
                ('lpFirstBlock', LPVOID),
                ('lpLastBlock', LPVOID)
            ]
        
        _anonymous_ = ['Block', 'Region']
        _fields_ = [
            ('Block', Block),
            ('Region', Region)
        ]
    
    _anonymous_ = ['DUMMYUNIONNAME']
    _fields_ = [
        ('lpData', PVOID),
        ('cbData', DWORD),
        ('cbOverhead', BYTE),
        ('iRegionIndex', BYTE),
        ('wFlags', WORD),
        ('DUMMYUNIONNAME', DUMMYUNIONNAME)
    ]

PROCESS_HEAP_ENTRY = _PROCESS_HEAP_ENTRY
PPROCESS_HEAP_ENTRY = POINTER(PROCESS_HEAP_ENTRY)
LPPROCESS_HEAP_ENTRY = PPROCESS_HEAP_ENTRY

PROCESS_HEAP_REGION = 0x1
PROCESS_HEAP_UNCOMMITTED_RANGE = 0x2
PROCESS_HEAP_ENTRY_BUSY = 0x4
PROCESS_HEAP_SEG_ALLOC = 0x8
PROCESS_HEAP_ENTRY_MOVEABLE = 0x10
PROCESS_HEAP_ENTRY_DDESHARE = 0x20

class _REASON_CONTEXT(Structure):
    class Reason(Union):
        class Detailed(Structure):
            _fields_ = [
                ('LocalizedReasonModule', HMODULE),
                ('LocalizedReasonId', ULONG),
                ('ReasonStringCount', ULONG),
                ('ReasonStrings', POINTER(LPWSTR))
            ]

        _anonymous_ = ['Detailed']
        _fields_ = [
            ('SimpleReasonString', LPWSTR),
            ('Detailed', Detailed)
        ]
    
    _anonymous_ = ['Reason']
    _fields_ = [
        ('Version', ULONG),
        ('Flags', DWORD),
        ('Reason', Reason)
    ]

REASON_CONTEXT = _REASON_CONTEXT
PREASON_CONTEXT = POINTER(REASON_CONTEXT)

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

PTHREAD_START_ROUTINE = POINTER(WINAPI(DWORD, LPVOID))
LPTHREAD_START_ROUTINE = PTHREAD_START_ROUTINE

PENCLAVE_ROUTINE = POINTER(WINAPI(LPVOID, LPVOID))
LPENCLAVE_ROUTINE = PENCLAVE_ROUTINE

class _EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ('ExceptionRecord', EXCEPTION_RECORD),
        ('dwFirstChance', DWORD)
    ]

EXCEPTION_DEBUG_INFO = _EXCEPTION_DEBUG_INFO
LPEXCEPTION_DEBUG_INFO = POINTER(EXCEPTION_DEBUG_INFO)

class _CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ('hThread', HANDLE),
        ('lpThreadLocalBase', LPVOID),
        ('lpStartAddress', LPTHREAD_START_ROUTINE)
    ]

CREATE_THREAD_DEBUG_INFO = _CREATE_THREAD_DEBUG_INFO
LPCREATE_THREAD_DEBUG_INFO = POINTER(CREATE_THREAD_DEBUG_INFO)

class _CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ('hFile', HANDLE),
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('lpBaseOfImage', LPVOID),
        ('dwDebugInfoFileOffset', DWORD),
        ('nDebugInfoSize', DWORD),
        ('lpThreadLocalBase', LPVOID),
        ('lpStartAddress', LPTHREAD_START_ROUTINE),
        ('lpImageName', LPVOID),
        ('fUnicode', WORD)
    ]

CREATE_PROCESS_DEBUG_INFO = _CREATE_PROCESS_DEBUG_INFO
LPCREATE_PROCESS_DEBUG_INFO = POINTER(CREATE_PROCESS_DEBUG_INFO)

class _EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [('dwExitCode', DWORD)]

EXIT_THREAD_DEBUG_INFO = _EXIT_THREAD_DEBUG_INFO
LPEXIT_THREAD_DEBUG_INFO = POINTER(EXIT_THREAD_DEBUG_INFO)

class _EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [('dwExitCode', DWORD)]

EXIT_PROCESS_DEBUG_INFO = _EXIT_PROCESS_DEBUG_INFO
LPEXIT_PROCESS_DEBUG_INFO = POINTER(EXIT_PROCESS_DEBUG_INFO)

class _LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ('hFile', HANDLE),
        ('lpBaseOfDll', LPVOID),
        ('dwDebugInfoFileOffset', DWORD),
        ('nDebugInfoSize', DWORD),
        ('lpImageName', LPVOID),
        ('fUnicode', WORD)
    ]

LOAD_DLL_DEBUG_INFO = _LOAD_DLL_DEBUG_INFO
LPLOAD_DLL_DEBUG_INFO = POINTER(LOAD_DLL_DEBUG_INFO)

class _UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [('lpBaseOfDll', LPVOID)]

UNLOAD_DLL_DEBUG_INFO = _UNLOAD_DLL_DEBUG_INFO
LPUNLOAD_DLL_DEBUG_INFO = POINTER(UNLOAD_DLL_DEBUG_INFO)

class _OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ('lpDebugStringData', LPSTR),
        ('fUnicode', WORD),
        ('nDebugStringLength', WORD)
    ]

OUTPUT_DEBUG_STRING_INFO = _OUTPUT_DEBUG_STRING_INFO
LPOUTPUT_DEBUG_STRING_INFO = POINTER(OUTPUT_DEBUG_STRING_INFO)

class _RIP_INFO(Structure):
    _fields_ = [
        ('dwError', DWORD),
        ('dwType', DWORD)
    ]

RIP_INFO = _RIP_INFO
LPRIP_INFO = POINTER(RIP_INFO)

class _DEBUG_EVENT(Structure):
    class u(Union):
        _fields_ = [
            ('Exception', EXCEPTION_DEBUG_INFO),
            ('CreateThread', CREATE_THREAD_DEBUG_INFO),
            ('CreateProcessInfo', CREATE_PROCESS_DEBUG_INFO),
            ('ExitThread', EXIT_THREAD_DEBUG_INFO),
            ('ExitProcess', EXIT_PROCESS_DEBUG_INFO),
            ('LoadDll', LOAD_DLL_DEBUG_INFO),
            ('UnloadDll', UNLOAD_DLL_DEBUG_INFO),
            ('DebugString', OUTPUT_DEBUG_STRING_INFO),
            ('RipInfo', RIP_INFO)
        ]
    
    _anonymous_ = ['u']
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", u)
    ]

DEBUG_EVENT = _DEBUG_EVENT
LPDEBUG_EVENT = POINTER(DEBUG_EVENT)

STILL_ACTIVE = STATUS_PENDING
EXCEPTION_ACCESS_VIOLATION = STATUS_ACCESS_VIOLATION
EXCEPTION_DATATYPE_MISALIGNMENT = STATUS_DATATYPE_MISALIGNMENT
EXCEPTION_BREAKPOINT = STATUS_BREAKPOINT
EXCEPTION_SINGLE_STEP = STATUS_SINGLE_STEP
EXCEPTION_ARRAY_BOUNDS_EXCEEDED = STATUS_ARRAY_BOUNDS_EXCEEDED
EXCEPTION_FLT_DENORMAL_OPERAND = STATUS_FLOAT_DENORMAL_OPERAND
EXCEPTION_FLT_DIVIDE_BY_ZERO = STATUS_FLOAT_DIVIDE_BY_ZERO
EXCEPTION_FLT_INEXACT_RESULT = STATUS_FLOAT_INEXACT_RESULT
EXCEPTION_FLT_INVALID_OPERATION = STATUS_FLOAT_INVALID_OPERATION
EXCEPTION_FLT_OVERFLOW = STATUS_FLOAT_OVERFLOW
EXCEPTION_FLT_STACK_CHECK = STATUS_FLOAT_STACK_CHECK
EXCEPTION_FLT_UNDERFLOW = STATUS_FLOAT_UNDERFLOW
EXCEPTION_INT_DIVIDE_BY_ZERO = STATUS_INTEGER_DIVIDE_BY_ZERO
EXCEPTION_INT_OVERFLOW = STATUS_INTEGER_OVERFLOW
EXCEPTION_PRIV_INSTRUCTION = STATUS_PRIVILEGED_INSTRUCTION
EXCEPTION_IN_PAGE_ERROR = STATUS_IN_PAGE_ERROR
EXCEPTION_ILLEGAL_INSTRUCTION = STATUS_ILLEGAL_INSTRUCTION
EXCEPTION_NONCONTINUABLE_EXCEPTION = STATUS_NONCONTINUABLE_EXCEPTION
EXCEPTION_STACK_OVERFLOW = STATUS_STACK_OVERFLOW
EXCEPTION_INVALID_DISPOSITION = STATUS_INVALID_DISPOSITION
EXCEPTION_GUARD_PAGE = STATUS_GUARD_PAGE_VIOLATION
EXCEPTION_INVALID_HANDLE = STATUS_INVALID_HANDLE
# EXCEPTION_POSSIBLE_DEADLOCK = STATUS_POSSIBLE_DEADLOCK
CONTROL_C_EXIT = STATUS_CONTROL_C_EXIT

LMEM_FIXED = 0x0
LMEM_MOVEABLE = 0x2
LMEM_NOCOMPACT = 0x10
LMEM_NODISCARD = 0x20
LMEM_ZEROINIT = 0x40
LMEM_MODIFY = 0x80
LMEM_DISCARDABLE = 0xf00
LMEM_VALID_FLAGS = 0xf72
LMEM_INVALID_HANDLE = 0x8000

LHND = (LMEM_MOVEABLE | LMEM_ZEROINIT)
LPTR = (LMEM_FIXED | LMEM_ZEROINIT)

NONZEROLHND = (LMEM_MOVEABLE)
NONZEROLPTR = (LMEM_FIXED)


def LocalReAlloc(hMem: int, uBytes: int, uFlags: int, errcheck: bool = True):
    LocalReAlloc = kernel32.LocalReAlloc
    LocalReAlloc.argtypes = [
        HLOCAL,
        SIZE_T,
        UINT
    ]

    LocalReAlloc.restype = HLOCAL
    res = LocalReAlloc(hMem, uBytes, uFlags)
    return win32_to_errcheck(res, errcheck)


def LocalDiscard(h: int, errcheck: bool = True): 
    return LocalReAlloc(h, 0, LMEM_MOVEABLE, errcheck)

LMEM_DISCARDED = 0x4000
LMEM_LOCKCOUNT = 0xff

NUMA_NO_PREFERRED_NODE = DWORD(-1).value
