# coding = 'utf-8'
'''Windows usually uses C data types.'''

import sys
import ctypes
from typing import Any, NoReturn
from ctypes import (
    wintypes, WINFUNCTYPE, CFUNCTYPE, Union, 
    Structure, byref, pointer, POINTER, WinError,
    WinDLL, CDLL, PyDLL, PYFUNCTYPE, sizeof, Array,
    LittleEndianUnion, LittleEndianStructure, LibraryLoader,
    get_last_error, set_last_error, set_errno, string_at,
    BigEndianStructure, BigEndianUnion, wstring_at, cast, 
    windll, cdll, create_string_buffer, create_unicode_buffer,
    addressof, FormatError, get_errno, pydll, ArgumentError
)

from ctypes import (
    c_bool, c_byte, c_char, c_char_p, c_double, c_float,
    c_int, c_int16, c_int32, c_int64, c_int8, c_buffer, 
    c_long, c_longdouble, c_longlong, c_short, c_size_t,
    c_ssize_t, c_ubyte, c_uint, c_uint16, c_uint32,
    c_uint64, c_uint8, c_ulong, c_ulonglong, c_ushort, c_void_p, 
    c_voidp, c_wchar, c_wchar_p, py_object
)

if sys.version_info >= (3, 13):
    from ctypes import c_time_t

if sys.version_info >= (3, 14):
    try:
        from ctypes import (
            c_longdouble_complex, c_float_complex, c_double_complex
        )
    except ImportError:
        pass

TRUE = True
FALSE = False

c_void = c_void_p
c_uchar = c_ubyte
c_wchar_t = c_wchar
c_int8_t = c_int8
c_int16_t = c_int16
c_int32_t = c_int32
c_int64_t = c_int64
c_uint8_t = c_uint8
c_uint16_t = c_uint16
c_uint32_t = c_uint32
c_uint64_t = c_uint64
c_wchar_t_p = c_wchar_tp = c_wchar_p

errno_t = c_int

ATOM = wintypes.ATOM
BOOL = wintypes.BOOL
BOOLEAN = wintypes.BOOLEAN
BYTE = wintypes.BYTE
CALLBACK = WINFUNCTYPE
CCHAR = wintypes.CHAR
CHAR = wintypes.CHAR
COLORREF = wintypes.COLORREF
DOUBLE = wintypes.DOUBLE
PDOUBLE = ctypes.POINTER(DOUBLE)
DWORD = wintypes.DWORD
DWORDLONG = ctypes.c_int64
DWORD_PTR = (ctypes.c_ulonglong 
             if sys.maxsize > 2**32 else ctypes.c_ulong
)
DWORD32 = ctypes.c_int32
DWORD64 = ctypes.c_int64
FLOAT = wintypes.FLOAT
HACCEL = wintypes.HACCEL
HALF_PTR = (ctypes.c_int 
            if sys.maxsize > 2**32 else ctypes.c_short
)
HANDLE = wintypes.HANDLE
HBITMAP = wintypes.HBITMAP
HBRUSH = wintypes.HBRUSH
HCOLORSPACE = wintypes.HCOLORSPACE
HCONV = wintypes.HANDLE
HCONVLIST = wintypes.HANDLE
HCURSOR = wintypes.HICON
HDC = wintypes.HDC
HDDEDATA = wintypes.HANDLE
HDESK = wintypes.HDESK
HDROP = wintypes.HANDLE
HDWP = wintypes.HDWP
HENHMETAFILE = wintypes.HENHMETAFILE
HFILE = ctypes.c_int
HFONT = wintypes.HFONT
HGDIOBJ = wintypes.HGDIOBJ
HGLOBAL = wintypes.HGLOBAL
HHOOK = wintypes.HHOOK
HICON = wintypes.HICON
HINSTANCE = wintypes.HINSTANCE
HKEY = wintypes.HKEY
HKL = wintypes.HKL
HLOCAL = wintypes.HLOCAL
HMENU = wintypes.HMENU
HMETAFILE = wintypes.HMETAFILE
HMODULE = wintypes.HMODULE
HMONITOR = wintypes.HMONITOR
HPALETTE = wintypes.HPALETTE
HPEN = wintypes.HPEN
HRESULT = wintypes.LONG
ht = HRESULT
HRGN = wintypes.HRGN
HRSRC = wintypes.HRSRC
HSZ = wintypes.HANDLE
HWINSTA = wintypes.HWINSTA
HWND = wintypes.HWND
INT = wintypes.INT
INT_PTR = (ctypes.c_int64 
           if sys.maxsize > 2**32 else ctypes.c_int
)
INT8 = ctypes.c_int8
INT16 = ctypes.c_int16
INT32 = ctypes.c_int32
INT64 = ctypes.c_int64
LANGID = wintypes.LANGID
LCID = wintypes.LCID
LCTYPE = wintypes.LCTYPE
LGRPID = wintypes.LGRPID
LONG = wintypes.LONG
LONGLONG = ctypes.c_long
LONG_PTR = ctypes.c_ulonglong
LONG32 = ctypes.c_int32
LONG64 = ctypes.c_int64
LPARAM = wintypes.LPARAM
LPBOOL = wintypes.LPBOOL
LPBYTE = wintypes.LPBYTE
LPCOLORREF = wintypes.LPCOLORREF
LPCSTR = wintypes.LPCSTR
LPCTSTR = (wintypes.LPCWSTR 
           if sys.maxunicode > 0xffff else wintypes.LPCSTR
)
LPCVOID = wintypes.LPCVOID
LPCWSTR = wintypes.LPCWSTR
LPDWORD = wintypes.LPDWORD
LPHANDLE = wintypes.LPHANDLE
LPINT = wintypes.LPINT
LPLONG = wintypes.LPLONG
LPSTR = wintypes.LPSTR
LPTSTR = (wintypes.LPWSTR 
          if sys.maxunicode > 0xffff else wintypes.LPSTR
)
LPVOID = wintypes.LPVOID
LPWORD = wintypes.LPWORD
LPWSTR = wintypes.LPWSTR
LRESULT = LONG_PTR
MAX_PATH = wintypes.MAX_PATH
NTSTATUS = wintypes.LONG
NULL = None
nullptr = None
PBOOL = wintypes.PBOOL
PBOOLEAN = wintypes.PBOOLEAN
PBYTE = wintypes.PBYTE
PCHAR = wintypes.PCHAR
PCSTR = wintypes.CHAR
PCTSTR = (wintypes.LPCWSTR 
          if sys.maxunicode > 0xffff else wintypes.LPCSTR
)
PCWSTR = ctypes.c_wchar_p
PDWORD = wintypes.PDWORD
PDWORDLONG = ctypes.POINTER(DWORDLONG)
PDWORD_STR = ctypes.POINTER(DWORD_PTR)
PDWORD32 = ctypes.POINTER(DWORD32)
PDWORD64 = ctypes.POINTER(DWORD64)
PFLOAT = wintypes.PFLOAT
PHALF_PTR = ctypes.POINTER(HALF_PTR)
PHANDLE = wintypes.PHANDLE
PHKEY = wintypes.PHKEY
PINT = wintypes.PINT
PINT_STR = ctypes.POINTER(INT_PTR)
PINT8 = ctypes.POINTER(INT8)
PINT16 = ctypes.POINTER(INT16)
PINT32 = ctypes.POINTER(INT32)
PINT64 = ctypes.POINTER(INT64)
PLCID = wintypes.PLCID
PLONG = wintypes.PLONG
PLONGLONG = ctypes.POINTER(LONGLONG)
PLONG_STR = ctypes.POINTER(LONG_PTR)
PLONG32 = ctypes.POINTER(LONG32)
PLONG64 = ctypes.POINTER(LONG64)
POINTER_32 = ctypes.POINTER(ctypes.c_uint32 
                            if sys.maxsize > 2**32 else ctypes.c_void_p
)
POINTER_64 = ctypes.POINTER(ctypes.c_uint64 
                            if sys.maxsize > 2**32 else ctypes.c_void_p
)

try:
    POINTER_SIGNID = ctypes.POINTER(ctypes.c_ssize_t)
except:
    POINTER_SIGNID = ctypes.POINTER(ctypes.c_int32 
                                    if ctypes.sizeof(ctypes.c_void_p) == 4 else ctypes.c_int64
    )

try:  
    POINTER_UNSINGID = ctypes.POINTER(ctypes.c_size_t)
except:
    POINTER_UNSINGID = ctypes.POINTER(ctypes.c_uint32 
                                      if ctypes.sizeof(ctypes.c_void_p) == 4 else ctypes.c_uint64
    )

PSHORT = wintypes.PSHORT
PSIZE_T = ctypes.POINTER(ctypes.c_int64 
                        if sys.maxsize > 2**32 else ctypes.c_long
)
PSSIZE_T = ctypes.POINTER(LONG_PTR)
PSTR = ctypes.POINTER(wintypes.CHAR)
PTBYTE = ctypes.POINTER(wintypes.WCHAR 
                        if sys.maxunicode > 0xffff else ctypes.c_char
)
PTCHAR = ctypes.POINTER(wintypes.WCHAR 
                        if sys.maxunicode > 0xffff else ctypes.c_char
)
PTSTR = ctypes.POINTER(wintypes.LPWSTR 
                       if sys.maxunicode > 0xffff else wintypes.LPSTR
)
PUCHAR = ctypes.POINTER(ctypes.c_ubyte)
PUHALF_PTR = ctypes.POINTER(ctypes.c_uint 
                            if sys.maxsize > 2**32 else ctypes.c_ushort
)
PUINT = wintypes.PUINT
PUINT_STR = ctypes.POINTER(ctypes.c_uint64 
                            if sys.maxsize > 2**32 else ctypes.c_uint
)
PUINT8 = ctypes.POINTER(ctypes.c_ubyte)
PUINT16 = ctypes.POINTER(ctypes.c_uint16)
PUINT32 = ctypes.POINTER(ctypes.c_uint32)
PUINT64 = ctypes.POINTER(ctypes.c_uint64)
PULONG = ctypes.POINTER(wintypes.PULONG)
PULONGLONG = ctypes.POINTER(ctypes.c_ulonglong)
PULONG_PTR = ctypes.POINTER(ctypes.c_uint64 
                            if sys.maxsize > 2**32 else ctypes.c_ulong
)
PULONG32 = ctypes.POINTER(ctypes.c_uint)
PULONG64 = ctypes.POINTER(ctypes.c_uint64)
PUSHORT = wintypes.PUSHORT
PVOID = ctypes.c_void_p
PWCHAR = wintypes.PWCHAR
PWORD = wintypes.PWORD
PWSTR = ctypes.POINTER(wintypes.WCHAR)
QWORD = ctypes.c_uint64
SC_HANDLE = wintypes.SC_HANDLE
SC_LOCK = LPVOID
SERVICE_STATUS_HANDLE = wintypes.SERVICE_STATUS_HANDLE
SHORT = wintypes.SHORT
SIZE_T = ctypes.c_size_t
SSIZE_T = ctypes.c_ssize_t
TBYTE = (wintypes.WCHAR 
         if sys.maxunicode > 0xffff else c_uchar
)
TCHAR = (wintypes.WCHAR 
         if sys.maxunicode > 0xffff else ctypes.c_char
)
UBYTE = ctypes.c_ubyte
UCHAR = ctypes.c_ubyte
UHALF_PTR = (ctypes.c_uint 
            if sys.maxsize > 2**32 else ctypes.c_ushort
)
UINT = wintypes.UINT
UINT_PTR = (ctypes.c_uint64 
             if sys.maxsize > 2**32 else ctypes.c_uint
)
UINT8 = ctypes.c_ubyte
UINT16 = ctypes.c_uint16
UINT32 = ctypes.c_uint32
UINT64 = ctypes.c_uint64
ULONG = wintypes.ULONG
ULONGLONG = ctypes.c_ulonglong
ULONG_PTR = (ctypes.c_uint64
              if sys.maxsize > 2**32 else ctypes.c_ulong
)
ULONG32 = ctypes.c_uint
ULONG64 = ctypes.c_uint64
USHORT = wintypes.USHORT
USN = LONGLONG
VOID = ctypes.c_void_p
WINBOOL = LONG
WCHAR = wintypes.WCHAR
WORD = wintypes.WORD
WPARAM = wintypes.WPARAM


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [('Length', USHORT), 
                ('MaximumLength', USHORT),
                ('Buffer', PWSTR)
        ]
    

UNICODE_STRING = _UNICODE_STRING
PUNICODE_STRING = ctypes.POINTER(_UNICODE_STRING)

WINAPI = WINFUNCTYPE
