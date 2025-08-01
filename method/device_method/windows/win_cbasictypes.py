# coding = 'utf-8'
'''Windows basic data types.'''

import sys
import ctypes
import platform
from ctypes import wintypes, WINFUNCTYPE

c_uchar = ctypes.c_ubyte

ATOM = wintypes.ATOM
BOOL = wintypes.BOOL
BOOLEAN = wintypes.BOOLEAN
BYTE = wintypes.BYTE
CALLBACK = WINFUNCTYPE
CCHAR = wintypes.CHAR
CHAR = wintypes.CHAR
COLORREF = wintypes.COLORREF
DWORD = wintypes.DWORD
DWORDLONG = ctypes.c_int64
DWORD_PTR = (ctypes.c_ulonglong 
             if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_ulong
)
DWORD32 = ctypes.c_int32
DWORD64 = ctypes.c_int64
FLOAT = wintypes.FLOAT
HACCEL = wintypes.HACCEL
HALF_PTR = (ctypes.c_int 
            if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_short
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
HRGN = wintypes.HRGN
HRSRC = wintypes.HRSRC
HSZ = wintypes.HANDLE
HWINSTA = wintypes.HWINSTA
HWND = wintypes.HWND
INT = wintypes.INT
INT_PTR = (ctypes.c_int64 
           if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_int
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
LONGLONG = (ctypes.c_int64 
            if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_double
)
LONG_PTR = ctypes.c_ulonglong
LONG32 = ctypes.c_int32
LONG64 = ctypes.c_int64
LPARAM = wintypes.LPARAM
LPBOOL = wintypes.LPBOOL
LPBYTE = wintypes.LPBYTE
LPCOLORREF = wintypes.LPCOLORREF
LPCSTR = wintypes.LPCSTR
LPCTSTR = (wintypes.LPCWSTR 
           if sys.version_info.major == 3 else wintypes.LPCSTR
)
LPCVOID = wintypes.LPCVOID
LPCWSTR = wintypes.LPCWSTR
LPDWORD = wintypes.LPDWORD
LPHANDLE = wintypes.LPHANDLE
LPINT = wintypes.LPINT
LPLONG = wintypes.LPLONG
LPSTR = wintypes.LPSTR
LPTSTR = (wintypes.LPWSTR 
          if sys.version_info.major == 3 else wintypes.LPSTR
)
LPVOID = wintypes.LPVOID
LPWORD = wintypes.LPWORD
LPWSTR = wintypes.LPWSTR
LRESULT = LONG_PTR
PBOOL = wintypes.PBOOL
PBOOLEAN = wintypes.PBOOLEAN
PBYTE = wintypes.PBYTE
PCHAR = wintypes.PCHAR
PCSTR = wintypes.CHAR
PCTSTR = (wintypes.LPCWSTR 
          if sys.version_info.major == 3 else wintypes.LPCSTR
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
                            if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_void_p
)
POINTER_64 = ctypes.POINTER(ctypes.c_uint64 
                            if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_void_p
)

try:
    POINTER_SIGNID = ctypes.POINTER(ctypes.c_ssize_t)
except Exception:
    POINTER_SIGNID = ctypes.POINTER(ctypes.c_int32 
                                    if ctypes.sizeof(ctypes.c_void_p) == 4 else ctypes.c_int64
    )

try:  
    POINTER_UNSINGID = ctypes.POINTER(ctypes.c_size_t)
except Exception:
    POINTER_UNSINGID = ctypes.POINTER(ctypes.c_uint32 
                                      if ctypes.sizeof(ctypes.c_void_p) == 4 else ctypes.c_uint64
    )

PSHORT = wintypes.PSHORT
PSIZE_T = ctypes.POINTER(ctypes.c_int64 
                        if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_long
)
PSSIZE_T = ctypes.POINTER(LONG_PTR)
PSTR = ctypes.POINTER(wintypes.CHAR)
PTBYTE = ctypes.POINTER(wintypes.WCHAR 
                        if sys.version_info.major == 3 else ctypes.c_char
)
PTCHAR = ctypes.POINTER(wintypes.WCHAR 
                        if sys.version_info.major == 3 else ctypes.c_char
)
PTSTR = ctypes.POINTER(wintypes.LPWSTR 
                       if sys.version_info == 3 else wintypes.LPSTR
)
PUCHAR = ctypes.POINTER(ctypes.c_ubyte)
PUHALF_PTR = ctypes.POINTER(ctypes.c_uint 
                            if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_ushort
)
PUINT = wintypes.PUINT
PUINT_STR = ctypes.POINTER(ctypes.c_uint64 
                            if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_uint
)
PUINT8 = ctypes.POINTER(ctypes.c_ubyte)
PUINT16 = ctypes.POINTER(ctypes.c_uint16)
PUINT32 = ctypes.POINTER(ctypes.c_uint32)
PUINT64 = ctypes.POINTER(ctypes.c_uint64)
PULONG = ctypes.POINTER(wintypes.PULONG)
PULONGLONG = ctypes.POINTER(ctypes.c_uint64 
                            if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_double
)
PULONG_PTR = ctypes.POINTER(ctypes.c_uint64 
                            if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_ulong
)
PULONG32 = ctypes.POINTER(ctypes.c_uint)
PULONG64 = ctypes.POINTER(ctypes.c_uint64)
PUSHORT = wintypes.PUSHORT
PVOID = ctypes.POINTER(ctypes.c_void_p)
PWCHAR = wintypes.PWCHAR
PWORD = wintypes.PWORD
PWSTR = ctypes.POINTER(wintypes.WCHAR)
QWORD = ctypes.c_uint64
SC_HANDLE = wintypes.SC_HANDLE
SC_LOCK = LPVOID
SERVICE_STATUS_HANDLE = wintypes.SERVICE_STATUS_HANDLE
SHORT = wintypes.SHORT
SIZE_T = (ctypes.c_uint64 
          if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_ulong
)
SSIZE_T = LONG_PTR
TBYTE = (wintypes.WCHAR 
         if sys.version_info.major == 3 else c_uchar
)
TCHAR = (wintypes.WCHAR 
         if sys.version_info.major == 3 else ctypes.c_char
)
UCHAR = ctypes.c_ubyte
UHALF_PTR = (ctypes.c_uint 
            if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_ushort
)
UINT = wintypes.UINT
UINT_PTR = (ctypes.c_uint64 
             if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_uint
)
UINT8 = ctypes.c_ubyte
UINT16 = ctypes.c_uint16
UINT32 = ctypes.c_uint32
UINT64 = ctypes.c_uint64
ULONG = wintypes.ULONG
ULONGLONG = (ctypes.c_uint64 
              if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_double
)
ULONG_PTR = (ctypes.c_uint64 
              if platform.machine().lower() == 'amd64' and sys.maxsize > 2**32 else ctypes.c_ulong
)
ULONG32 = ctypes.c_uint
ULONG64 = ctypes.c_uint64
USHORT = wintypes.USHORT
USN = LONGLONG
VOID = ctypes.c_void_p
WCHAR = wintypes.WCHAR
WORD = wintypes.WORD
WPARAM = wintypes.WPARAM
WINAPI = WINFUNCTYPE


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [('Length', USHORT), 
                ('MaximumLength', USHORT),
                ('Buffer', PWSTR)
        ]
    

UNICODE_STRING = _UNICODE_STRING
PUNICODE_STRING = ctypes.POINTER(_UNICODE_STRING)

