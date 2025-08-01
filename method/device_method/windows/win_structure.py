# coding = 'utf-8'

import ctypes
from .win_cbasictypes import *

DWORD16 = DWORD * 16

UCHAR8 = UCHAR * 8
WCHAR64 = WCHAR * 64
WCHAR128 = WCHAR * 128
WCHAR256 = WCHAR * 256

MSGBOXCALLBACK = VOID
TASKDIALOG_COMMON_BUTTON_FLAGS = INT
TASKDIALOG_FLAGS = INT
PFTASKDIALOGCALLBACK = ctypes.WINFUNCTYPE(
    HRESULT,
    HWND,
    UINT,
    WPARAM,
    LPARAM,
    LONG_PTR
)


class TASKDIALOGICON(ctypes.Union):
    _pack_ = 1
    _fields_ = [('hMainIcon', HICON), 
                ('pszMainIcon', PCWSTR)
    ]


class TASKDIALOGFOOTICON(ctypes.Union):
    _pack_ = 1
    _fields_ = [('hFooterIcon', HICON), 
                ('pszFooterIcon', PCWSTR)
    ]


class TASKDIALOG_BUTTON(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('nButtonID', INT), 
                ('pszButtonText', PCWSTR)
    ]


class _TASKDIALOGCONFIG(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('cbSize', UINT), 
                ('hwndParent', HWND),
                ('hInstance', HINSTANCE),
                ('dwFlags', TASKDIALOG_FLAGS),
                ('dwCommonButtons', TASKDIALOG_COMMON_BUTTON_FLAGS),
                ('pszWindowTitle', PCWSTR),
                ('MainIcon', TASKDIALOGICON),
                ('pszMainInstruction', PCWSTR),
                ('pszContent', PCWSTR),
                ('cButtons', UINT),
				('pButtons', ctypes.POINTER(TASKDIALOG_BUTTON)),
                ('nDefaultButton', INT),
                ('cRadioButtons', UINT),
				('pRadioButtons', ctypes.POINTER(TASKDIALOG_BUTTON)),
                ('nDefaultRadioButton', INT),
                ('pszVerificationText', PCWSTR),
                ('pszExpandedInformation', PCWSTR),
                ('pszExpandedControlText', PCWSTR),
                ('pszCollapsedControlText', PCWSTR),
                ('FooterIcon', TASKDIALOGFOOTICON),
                ('pszFooter', PCWSTR),
                ('pfCallback', PFTASKDIALOGCALLBACK),
                ('lpCallbackData', LONG_PTR),
                ('cxWidth', UINT)
    ]


class DLGITEMTEMPLATE(ctypes.Structure):
    _fields_ = [('style', DWORD),
                ('dwExtendedStyle', DWORD),
                ('x', SHORT),
                ('y', SHORT),
                ('cx', SHORT),
                ('cy', SHORT),
                ('id', WORD)
    ]


class DLGTEMPLATE(ctypes.Structure):
    _fields_ = [('style', DWORD),
                ('dwExtendedStyle', DWORD),
                ('cdit', WORD),
                ('x', SHORT),
                ('y', SHORT),
                ('cx', SHORT),
                ('cy', SHORT)
    ]


'''
class DLGITEMTEMPLATEEX(ctypes.Structure):
    _fields_ = [('helpID', DWORD),
                ('exStyle', DWORD),
                ('style', DWORD),
                ('x', SHORT),
                ('y', SHORT),
                ('cx', SHORT),
                ('cy', SHORT),
                ('id', DWORD),
                ('windowClass', DWORD16),
                ('title', DWORD16),
                ('extraCount', WORD)
    ]
'''


class tagMSGBOXPARAMSW(ctypes.Structure):
    _fields_ = [
        ("cbSize", UINT),
        ("hwndOwner", HWND),
        ("hInstance", HINSTANCE),
        ("lpszText", LPCWSTR),
        ("lpszCaption", LPCWSTR),
        ("dwStyle", DWORD),
        ("lpszIcon", LPCWSTR),
        ("dwContextHelpId", DWORD_PTR),
        ("lpfnMsgBoxCallback", MSGBOXCALLBACK),
        ("dwLanguageId", DWORD),
    ]


class tagMSGBOXPARAMSA(ctypes.Structure):
    _fields_ = [
        ("cbSize", UINT),
        ("hwndOwner", HWND),
        ("hInstance", HINSTANCE),
        ("lpszText", LPCSTR),
        ("lpszCaption", LPCSTR),
        ("dwStyle", DWORD),
        ("lpszIcon", LPCSTR),
        ("dwContextHelpId", DWORD_PTR),
        ("lpfnMsgBoxCallback", MSGBOXCALLBACK),
        ("dwLanguageId", DWORD),
    ]


class _SHELLEXECUTEINFOW(ctypes.Structure):
    class SHELLEXECUTEICON(ctypes.Union):
        _fields_ = [('hIcon', HANDLE), 
                    ('hMonitor', HANDLE)
        ]

    _fields_ = [('cbSize', DWORD), 
                ('fMask', ULONG),
                ('hwnd', HWND),
                ('lpVerb', LPCWSTR),
                ('lpFile', LPCWSTR),
                ('lpParameters', LPCWSTR),
                ('lpDirectory', LPCWSTR),
                ('nShow', INT),
                ('hInstApp', HINSTANCE),
                ('lpIDList', VOID),
                ('lpClass', LPCWSTR),
                ('hkeyClass', HKEY),
                ('dwHotKey', DWORD),
                ('hIcon_Monitor', SHELLEXECUTEICON),
                ('hProcess', HANDLE)
    ]


class _SHELLEXECUTEINFOA(ctypes.Structure):
    class SHELLEXECUTEICON(ctypes.Union):
        _fields_ = [('hIcon', HANDLE), 
                    ('hMonitor', HANDLE)
        ]

    _fields_ = [('cbSize', DWORD),
                ('fMask', ULONG),
                ('hwnd', HWND),
                ('lpVerb', LPCSTR),
                ('lpFile', LPCSTR),
                ('lpParameters', LPCSTR),
                ('lpDirectory', LPCSTR),
                ('nShow', INT),
                ('hInstApp', HINSTANCE),
                ('lpIDList', VOID),
                ('lpClass', LPCSTR),
                ('hkeyClass', HKEY),
                ('dwHotKey', DWORD),
                ('hIcon_Monitor', SHELLEXECUTEICON),
                ('hProcess', HANDLE)
    ]


class _GUID(ctypes.Structure):
    _fields_ = [('Data1', ULONG32), 
                ('Data2', USHORT),
                ('Data3', USHORT),
                ('Data4', UCHAR8)
    ]


class UTIMEVER(ctypes.Union):
    _fields_ = [('uTimeout', UINT), 
                ('uVersion', UINT)
    ]


GUID = _GUID
TASKDIALOGCONFIG = _TASKDIALOGCONFIG

MSGBOXPARAMSA = tagMSGBOXPARAMSA
PMSGBOXPARAMSA = ctypes.POINTER(tagMSGBOXPARAMSA)
LPMSGBOXPARAMSA = PMSGBOXPARAMSA

MSGBOXPARAMSW = tagMSGBOXPARAMSW
PMSGBOXPARAMSW = ctypes.POINTER(tagMSGBOXPARAMSW)
LPMSGBOXPARAMSW = PMSGBOXPARAMSW

SHELLEXECUTEINFOW = _SHELLEXECUTEINFOW
LPSHELLEXECUTEINFOW = ctypes.POINTER(SHELLEXECUTEINFOW)

SHELLEXECUTEINFOA = _SHELLEXECUTEINFOA
LPSHELLEXECUTEINFOA = ctypes.POINTER(SHELLEXECUTEINFOA)


class _NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [('cbSize', DWORD), 
                ('hWnd', HWND), 
                ('uID', UINT), 
                ('uFlags', UINT), 
                ('uCallbackMessage', UINT), 
                ('hIcon', HICON), 
                ('szTip', WCHAR128), 
                ('dwState', DWORD), 
                ('dwStateMask', DWORD), 
                ('szInfo', WCHAR256), 
                ('uTimeVer', UTIMEVER), 
                ('szInfoTitle', WCHAR64), 
                ('dwInfoFlags', DWORD), 
                ('guidItem', GUID)
    ]


NOTIFYICONDATAW = _NOTIFYICONDATAW


class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Length', ULONG),
                ('RootDirectory', HANDLE),
                ('ObjectName', PUNICODE_STRING),
                ('Attributes', ULONG),
                ('SecurityDescriptor', PVOID),
                ('SecurityQualityOfService', PVOID)
    ]


class _CLIENT_ID(ctypes.Structure):
    _fields_ = [('UniqueProcess', HANDLE),
                ('UniqueThread', HANDLE)
    ]


ACCESS_MASK = ULONG
OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES
POBJECT_ATTRIBUTES = ctypes.POINTER(OBJECT_ATTRIBUTES)
CLIENT_ID = _CLIENT_ID
PCLIENT_ID = ctypes.POINTER(CLIENT_ID)

