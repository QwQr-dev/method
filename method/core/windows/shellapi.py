# coding = 'utf-8'
# shellapi.h

import enum
import ctypes
from typing import Any
from ctypes import Structure, POINTER, WinError


try:
    from sdkddkver import *
    from guiddef import GUID
    from public_dll import *
    from win_cbasictypes import *
    from error import GetLastError
    from windef import POINT, RECT
    from processthreadsapi import *
    from winuser import WM_USER, SendMessage
    from wtypesbase import LPSECURITY_ATTRIBUTES
except ImportError:
    from .sdkddkver import *
    from .guiddef import GUID
    from .public_dll import *
    from .win_cbasictypes import *
    from .error import GetLastError
    from .windef import POINT, RECT
    from .processthreadsapi import *
    from .winuser import WM_USER, SendMessage
    from .wtypesbase import LPSECURITY_ATTRIBUTES

NULL = 0

_WIN32_IE = WIN32_IE
MAX_PATH = 260

CHAR64 = CHAR * 64
CHAR128 = CHAR * 128
CHAR256 = CHAR * 256
WINBOOL = BOOL

MAX_PATH = 260

verbs = ['edit', 
         'explore', 
         'find', 
         'open', 
         'openas', 
         'print', 
         'properties', 
         'runas'
]

# shellapi.h

class _DRAGINFOA(Structure):
    _fields_ = [('uSize', UINT),
                ('pt', POINT),
                ('fNC', WINBOOL),
                ('lpFileList', LPSTR),
                ('grfKeyState', DWORD),
    ]

DRAGINFOA = _DRAGINFOA
PDRAGINFOA = POINTER(DRAGINFOA)

class _DRAGINFOW(Structure):
    _fields_ = [('uSize', UINT),
                ('pt', POINT),
                ('fNC', WINBOOL),
                ('lpFileList', LPWSTR),
                ('grfKeyState', DWORD),
    ]

DRAGINFOW = _DRAGINFOW
PDRAGINFOW = POINTER(DRAGINFOW)

ABM_NEW = 0x00000000
ABM_REMOVE = 0x00000001
ABM_QUERYPOS = 0x00000002
ABM_SETPOS = 0x00000003
ABM_GETSTATE = 0x00000004
ABM_GETTASKBARPOS = 0x00000005
ABM_ACTIVATE = 0x00000006
ABM_GETAUTOHIDEBAR = 0x00000007
ABM_SETAUTOHIDEBAR = 0x00000008

ABM_WINDOWPOSCHANGED = 0x0000009
ABM_SETSTATE = 0x0000000a

if NTDDI_VERSION >= 0x06020000:
    ABM_GETAUTOHIDEBAREX = 0x0000000b
    ABM_SETAUTOHIDEBAREX = 0x0000000c

ABN_STATECHANGE = 0x0000000
ABN_POSCHANGED = 0x0000001
ABN_FULLSCREENAPP = 0x0000002
ABN_WINDOWARRANGE = 0x0000003

ABS_AUTOHIDE = 0x0000001
ABS_ALWAYSONTOP = 0x0000002

ABE_LEFT = 0
ABE_TOP = 1
ABE_RIGHT = 2
ABE_BOTTOM = 3

class _AppBarData(Structure):
    _fields_ = [("cbSize", DWORD),
                ("hWnd", HWND),
                ("uCallbackMessage", UINT),
                ("uEdge", UINT),
                ("rc", RECT),
                ("lParam", LPARAM),
    ]

APPBARDATA = _AppBarData
PAPPBARDATA = POINTER(APPBARDATA)


def EIRESID(x):
    return -1 * INT(x).value


FO_MOVE = 0x1
FO_COPY = 0x2
FO_DELETE = 0x3
FO_RENAME = 0x4

FOF_MULTIDESTFILES = 0x1
FOF_CONFIRMMOUSE = 0x2
FOF_SILENT = 0x4
FOF_RENAMEONCOLLISION = 0x8
FOF_NOCONFIRMATION = 0x10
FOF_WANTMAPPINGHANDLE = 0x20
FOF_ALLOWUNDO = 0x40
FOF_FILESONLY = 0x80
FOF_SIMPLEPROGRESS = 0x100
FOF_NOCONFIRMMKDIR = 0x200
FOF_NOERRORUI = 0x400
FOF_NOCOPYSECURITYATTRIBS = 0x800
FOF_NORECURSION = 0x1000
FOF_NO_CONNECTED_ELEMENTS = 0x2000
FOF_WANTNUKEWARNING = 0x4000
FOF_NORECURSEREPARSE = 0x8000

FOF_NO_UI = (FOF_SILENT | 
             FOF_NOCONFIRMATION | 
             FOF_NOERRORUI | 
             FOF_NOCONFIRMMKDIR
)

FILEOP_FLAGS = WORD

PO_DELETE = 0x0013
PO_RENAME = 0x0014
PO_PORTCHANGE = 0x0020

PO_REN_PORT = 0x0034

PRINTEROP_FLAGS = WORD

class _SHFILEOPSTRUCTA(Structure):
    _fields_ = [('hwnd', HWND),
                ('wFunc', UINT),
                ('pFrom', LPCSTR),
                ('pTo', LPCSTR),
                ('fFlags', FILEOP_FLAGS),
                ('fAnyOperationsAborted', WINBOOL),
                ('hNameMappings', LPVOID),
                ('lpszProgressTitle', PCSTR),
    ]

SHFILEOPSTRUCTA = _SHFILEOPSTRUCTA
PSHFILEOPSTRUCTA = POINTER(SHFILEOPSTRUCTA)

class _SHFILEOPSTRUCTW(Structure):
    _fields_ = [('hwnd', HWND),
                ('wFunc', UINT),
                ('pFrom', LPCWSTR),
                ('pTo', LPCWSTR),
                ('fFlags', FILEOP_FLAGS),
                ('fAnyOperationsAborted', WINBOOL),
                ('hNameMappings', LPVOID),
                ('lpszProgressTitle', PCWSTR),
    ]

SHFILEOPSTRUCTW = _SHFILEOPSTRUCTW
PSHFILEOPSTRUCTW = POINTER(SHFILEOPSTRUCTW)

class _SHNAMEMAPPINGA(Structure):
    _fields_ = [('pszOldPath', LPSTR),
                ('pszNewPath', LPSTR),
                ('cchOldPath', INT),
                ('cchNewPath', INT),
    ]

SHNAMEMAPPINGA = _SHNAMEMAPPINGA
PSHNAMEMAPPINGA = POINTER(SHNAMEMAPPINGA)

class _SHNAMEMAPPINGW(Structure):
    _fields_ = [('pszOldPath', LPWSTR),
                ('pszNewPath', LPWSTR),
                ('cchOldPath', INT),
                ('cchNewPath', INT),
    ]

SHNAMEMAPPINGW = _SHNAMEMAPPINGW
PSHNAMEMAPPINGW = POINTER(SHNAMEMAPPINGW)

SE_ERR_FNF = 2
SE_ERR_PNF = 3
SE_ERR_ACCESSDENIED = 5
SE_ERR_OOM = 8
SE_ERR_DLLNOTFOUND = 32

SE_ERR_SHARE = 26
SE_ERR_ASSOCINCOMPLETE = 27
SE_ERR_DDETIMEOUT = 28
SE_ERR_DDEFAIL = 29
SE_ERR_DDEBUSY = 30
SE_ERR_NOASSOC = 31

SEE_MASK_DEFAULT = 0x0
SEE_MASK_CLASSNAME = 0x1
SEE_MASK_CLASSKEY = 0x3

SEE_MASK_IDLIST = 0x4
SEE_MASK_INVOKEIDLIST = 0xc

if NTDDI_VERSION < 0x06000000:
    SEE_MASK_ICON = 0x10

SEE_MASK_HOTKEY = 0x20
SEE_MASK_NOCLOSEPROCESS = 0x40
SEE_MASK_CONNECTNETDRV = 0x80
SEE_MASK_NOASYNC = 0x100
SEE_MASK_FLAG_DDEWAIT = SEE_MASK_NOASYNC
SEE_MASK_DOENVSUBST = 0x200
SEE_MASK_FLAG_NO_UI = 0x400
SEE_MASK_UNICODE = 0x4000
SEE_MASK_NO_CONSOLE = 0x8000
SEE_MASK_ASYNCOK = 0x100000
SEE_MASK_HMONITOR = 0x200000
SEE_MASK_NOZONECHECKS = 0x800000
SEE_MASK_NOQUERYCLASSSTORE = 0x1000000
SEE_MASK_WAITFORINPUTIDLE = 0x2000000
SEE_MASK_FLAG_LOG_USAGE = 0x4000000

EXEC_SEPARATE_VDM       =         0x00000001
EXEC_NO_CONSOLE         =         0x00000002
SEE_MASK_FLAG_SHELLEXEC =         0x00000800
SEE_MASK_FORCENOIDLIST  =         0x00001000
SEE_MASK_NO_HOOKS       =         0x00002000
SEE_MASK_HASLINKNAME    =         0x00010000
SEE_MASK_FLAG_SEPVDM    =         0x00020000
SEE_MASK_RESERVED       =         0x00040000
SEE_MASK_HASTITLE       =         0x00080000
SEE_MASK_FILEANDURL     =         0x00400000
SEE_VALID_CMIC_BITS     =         0x348FAFF0
SEE_VALID_CMIC_FLAGS    =         0x048FAFC0
SEE_MASK_VALID          =         0x07FFFFFF

SW_HIDE = 0
SW_SHOWNORMAL = 1
SW_NORMAL = 1
SW_SHOWMINIMIZED = 2
SW_SHOWMAXIMIZED = 3
SW_MAXIMIZE = 3
SW_SHOWNOACTIVATE = 4
SW_SHOW = 5
SW_MINIMIZE = 6
SW_SHOWMINNOACTIVE = 7
SW_SHOWMINNOACTIVE = 8
SW_RESTORE = 9
SW_SHOWDEFAULT = 10
SW_FORCEMINIMIZE = 11

if NTDDI_VERSION >= 0x06020000:
    SEE_MASK_FLAG_HINST_IS_SITE = 0x8000000

class SHELLEXECUTEICON(ctypes.Union):
    _fields_ = [('hIcon', HANDLE), 
                ('hMonitor', HANDLE)
    ]
    
class _SHELLEXECUTEINFOW(ctypes.Structure):
    class SHELLEXECUTEICON(ctypes.Union):
        _fields_ = [('hIcon', HANDLE), 
                    ('hMonitor', HANDLE)
        ]

    _anonymous_ = ['SHELLEXECUTEICON']
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
                ('SHELLEXECUTEICON', SHELLEXECUTEICON),
                ('hProcess', HANDLE)
    ]

class _SHELLEXECUTEINFOA(ctypes.Structure):
    class SHELLEXECUTEICON(ctypes.Union):
        _fields_ = [('hIcon', HANDLE), 
                    ('hMonitor', HANDLE)
        ]

    _anonymous_ = ['SHELLEXECUTEICON']
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
                ('SHELLEXECUTEICON', SHELLEXECUTEICON),
                ('hProcess', HANDLE)
    ]

SHELLEXECUTEINFOW = _SHELLEXECUTEINFOW
LPSHELLEXECUTEINFOW = ctypes.POINTER(SHELLEXECUTEINFOW)

SHELLEXECUTEINFOA = _SHELLEXECUTEINFOA
LPSHELLEXECUTEINFOA = ctypes.POINTER(SHELLEXECUTEINFOA)

SHELLEXECUTEINFO = SHELLEXECUTEINFOW if UNICODE else SHELLEXECUTEINFOA
LPSHELLEXECUTEINFO = LPSHELLEXECUTEINFOW if UNICODE else LPSHELLEXECUTEINFOA

class _SHCREATEPROCESSINFOW(Structure):
    _fields_ = [('cbSize', DWORD),
                ('fMask', ULONG),
                ('hwnd', HWND),
                ('pszFile', LPCWSTR),
                ('pszParameters', LPCWSTR),
                ('pszCurrentDirectory', LPCWSTR),
                ('hUserToken', HANDLE),
                ('lpProcessAttributes', LPSECURITY_ATTRIBUTES),
                ('lpThreadAttributes', LPSECURITY_ATTRIBUTES),
                ('bInheritHandles', WINBOOL),
                ('dwCreationFlags', DWORD),
                ('lpStartupInfo', LPSTARTUPINFOW),
                ('lpProcessInformation', LPPROCESS_INFORMATION),
    ]

SHCREATEPROCESSINFOW = _SHCREATEPROCESSINFOW
PSHCREATEPROCESSINFOW = POINTER(SHCREATEPROCESSINFOW)

if NTDDI_VERSION >= 0x06000000:
    ASSOCCLASS_SHELL_KEY = 0
    ASSOCCLASS_PROGID_KEY = 1
    ASSOCCLASS_PROGID_STR = 2
    ASSOCCLASS_CLSID_KEY = 3
    ASSOCCLASS_CLSID_STR = 4
    ASSOCCLASS_APP_KEY = 5
    ASSOCCLASS_APP_STR = 6
    ASSOCCLASS_SYSTEM_STR = 7
    ASSOCCLASS_FOLDER = 8
    ASSOCCLASS_STAR = 9

    if NTDDI_VERSION >= 0x06020000:
        ASSOCCLASS_FIXED_PROGID_STR = 10
        ASSOCCLASS_PROTOCOL_STR = 11

    class ASSOCCLASS(enum.IntFlag):
        ASSOCCLASS_SHELL_KEY = 0
        ASSOCCLASS_PROGID_KEY = 1
        ASSOCCLASS_PROGID_STR = 2
        ASSOCCLASS_CLSID_KEY = 3
        ASSOCCLASS_CLSID_STR = 4
        ASSOCCLASS_APP_KEY = 5
        ASSOCCLASS_APP_STR = 6
        ASSOCCLASS_SYSTEM_STR = 7
        ASSOCCLASS_FOLDER = 8
        ASSOCCLASS_STAR = 9

        if NTDDI_VERSION >= 0x06020000:
            ASSOCCLASS_FIXED_PROGID_STR = 10
            ASSOCCLASS_PROTOCOL_STR = 11
        
    class ASSOCIATIONELEMENT(Structure):
        _fields_ = [('ac', UINT),
                    ('hkClass', HKEY),
                    ('pszClass', PCWSTR),
        ]

SHERB_NOCONFIRMATION = 0x00000001
SHERB_NOPROGRESSUI = 0x00000002
SHERB_NOSOUND = 0x00000004

QUNS_NOT_PRESENT = 1
QUNS_BUSY = 2
QUNS_RUNNING_D3D_FULL_SCREEN = 3
QUNS_PRESENTATION_MODE = 4
QUNS_ACCEPTS_NOTIFICATIONS = 5

if NTDDI_VERSION >= 0x06000000:
    if NTDDI_VERSION >= 0x06010000:
        QUNS_QUIET_TIME = 6

    if NTDDI_VERSION >= 0x06020000:
        QUNS_APP = 7

    class QUERY_USER_NOTIFICATION_STATE(enum.IntFlag):
        QUNS_NOT_PRESENT = 1
        QUNS_BUSY = 2
        QUNS_RUNNING_D3D_FULL_SCREEN = 3
        QUNS_PRESENTATION_MODE = 4
        QUNS_ACCEPTS_NOTIFICATIONS = 5

        if NTDDI_VERSION >= 0x06010000:
            QUNS_QUIET_TIME = 6

        if NTDDI_VERSION >= 0x06020000:
            QUNS_APP = 7

class _NOTIFYICONDATAA(ctypes.Structure):
    class UTIMEVER(ctypes.Union):
        _fields_ = [('uTimeout', UINT), 
                    ('uVersion', UINT)
        ]

    _fields_ = [('cbSize', DWORD), 
                ('hWnd', HWND), 
                ('uID', UINT), 
                ('uFlags', UINT), 
                ('uCallbackMessage', UINT), 
                ('hIcon', HICON), 
                ('szTip', CHAR128), 
                ('dwState', DWORD), 
                ('dwStateMask', DWORD), 
                ('szInfo', CHAR256), 
                ('uTimeVer', UTIMEVER), 
                ('szInfoTitle', CHAR64), 
                ('dwInfoFlags', DWORD), 
                ('guidItem', GUID)
    ]

    if NTDDI_VERSION >= 0x06000000:
        _fields_.append(('hBalloonIcon', HICON))
    
NOTIFYICONDATAA = _NOTIFYICONDATAA
PNOTIFYICONDATAA = POINTER(NOTIFYICONDATAA)

class _NOTIFYICONDATAW(ctypes.Structure):
    class UTIMEVER(ctypes.Union):
        _fields_ = [('uTimeout', UINT), 
                ('uVersion', UINT)
        ]

    _fields_ = [('cbSize', DWORD), 
                ('hWnd', HWND), 
                ('uID', UINT), 
                ('uFlags', UINT), 
                ('uCallbackMessage', UINT), 
                ('hIcon', HICON), 
                ('szTip', WCHAR * 128), 
                ('dwState', DWORD), 
                ('dwStateMask', DWORD), 
                ('szInfo', WCHAR * 256), 
                ('uTimeVer', UTIMEVER), 
                ('szInfoTitle', WCHAR * 64), 
                ('dwInfoFlags', DWORD), 
                ('guidItem', GUID)
    ]

    if NTDDI_VERSION >= 0x06000000:
        _fields_.append(('hBalloonIcon', HICON))
    
NOTIFYICONDATAW = _NOTIFYICONDATAW

NIN_SELECT = (WM_USER + 0)
NINF_KEY = 0x1
NIN_KEYSELECT = (NIN_SELECT | NINF_KEY)

NIN_BALLOONSHOW = (WM_USER + 2)
NIN_BALLOONHIDE = (WM_USER + 3)
NIN_BALLOONTIMEOUT = (WM_USER + 4)
NIN_BALLOONUSERCLICK = (WM_USER + 5)

if NTDDI_VERSION >= 0x06000000:
    NIN_POPUPOPEN = (WM_USER + 6)
    NIN_POPUPCLOSE = (WM_USER + 7)

NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIM_SETFOCUS = 0x00000003
NIM_SETVERSION = 0x00000004

NOTIFYICON_VERSION = 3

if NTDDI_VERSION >= 0x06000000:
    NOTIFYICON_VERSION_4 = 4

NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_STATE = 0x00000008
NIF_INFO = 0x00000010

if _WIN32_IE >= 0x600:
    NIF_GUID = 0x00000020

if NTDDI_VERSION >= 0x06000000:
    NIF_REALTIME = 0x00000040
    NIF_SHOWTIP = 0x00000080

NIS_HIDDEN = 0x00000001
NIS_SHAREDICON = 0x00000002

NIIF_NONE = 0x00000000
NIIF_INFO = 0x00000001
NIIF_WARNING = 0x00000002
NIIF_ERROR = 0x00000003
NIIF_USER = 0x00000004
NIIF_ICON_MASK = 0x0000000f
NIIF_NOSOUND = 0x00000010

if NTDDI_VERSION >= 0x06000000:
    NIIF_LARGE_ICON = 0x00000020

if NTDDI_VERSION >= 0x06010000:
    NIIF_RESPECT_QUIET_TIME = 0x00000080

class _NOTIFYICONIDENTIFIER(Structure):
    _fields_ = [('cbSize', DWORD),
                ('hWnd', HWND),
                ('uID', UINT),
                ('guidItem', GUID),
    ]

NOTIFYICONIDENTIFIER = _NOTIFYICONIDENTIFIER
PNOTIFYICONIDENTIFIER = POINTER(NOTIFYICONIDENTIFIER)

class _SHFILEINFOA(Structure):
    _fields_ = [('hIcon', HICON),
                ('iIcon', INT),
                ('dwAttributes', DWORD),
                ('szDisplayName', CHAR * MAX_PATH),
                ('szTypeName', CHAR * 80),
    ]

SHFILEINFOA = _SHFILEINFOA

class _SHFILEINFOW(Structure):
    _fields_ = [('hIcon', HICON),
                ('iIcon', INT),
                ('dwAttributes', DWORD),
                ('szDisplayName', WCHAR * MAX_PATH),
                ('szTypeName', WCHAR * 80),
    ]

SHFILEINFOW = _SHFILEINFOW

SHGFI_ICON = 0x000000100
SHGFI_DISPLAYNAME = 0x000000200
SHGFI_TYPENAME = 0x000000400
SHGFI_ATTRIBUTES = 0x000000800
SHGFI_ICONLOCATION = 0x000001000
SHGFI_EXETYPE = 0x000002000
SHGFI_SYSICONINDEX = 0x000004000
SHGFI_LINKOVERLAY = 0x000008000
SHGFI_SELECTED = 0x000010000
SHGFI_ATTR_SPECIFIED = 0x000020000

SHGFI_LARGEICON = 0x000000000
SHGFI_SMALLICON = 0x000000001
SHGFI_OPENICON = 0x000000002
SHGFI_SHELLICONSIZE = 0x000000004
SHGFI_PIDL = 0x000000008
SHGFI_USEFILEATTRIBUTES = 0x000000010

SHGFI_ADDOVERLAYS = 0x000000020
SHGFI_OVERLAYINDEX = 0x000000040

if NTDDI_VERSION >= 0x06000000:
    class _SHSTOCKICONINFO(Structure):
        _fields_ = [('cbSize', DWORD),
                    ('hIcon', HICON),
                    ('iSysImageIndex', INT),
                    ('iIcon', INT),
                    ('szPath', WCHAR * MAX_PATH),
        ]

    SHSTOCKICONINFO = _SHSTOCKICONINFO

    SHGSI_ICONLOCATION = 0
    SHGSI_ICON = SHGFI_ICON
    SHGSI_SYSICONINDEX = SHGFI_SYSICONINDEX
    SHGSI_LINKOVERLAY = SHGFI_LINKOVERLAY
    SHGSI_SELECTED = SHGFI_SELECTED
    SHGSI_LARGEICON = SHGFI_LARGEICON
    SHGSI_SMALLICON = SHGFI_SMALLICON
    SHGSI_SHELLICONSIZE = SHGFI_SHELLICONSIZE

    SIID_DOCNOASSOC = 0
    SIID_DOCASSOC = 1
    SIID_APPLICATION = 2
    SIID_FOLDER = 3
    SIID_FOLDEROPEN = 4
    SIID_DRIVE525 = 5
    SIID_DRIVE35 = 6
    SIID_DRIVEREMOVE = 7
    SIID_DRIVEFIXED = 8
    SIID_DRIVENET = 9
    SIID_DRIVENETDISABLED = 10
    SIID_DRIVECD = 11
    SIID_DRIVERAM = 12
    SIID_WORLD = 13
    SIID_SERVER = 15
    SIID_PRINTER = 16
    SIID_MYNETWORK = 17
    SIID_FIND = 22
    SIID_HELP = 23
    SIID_SHARE = 28
    SIID_LINK = 29
    SIID_SLOWFILE = 30
    SIID_RECYCLER = 31
    SIID_RECYCLERFULL = 32
    SIID_MEDIACDAUDIO = 40
    SIID_LOCK = 47
    SIID_AUTOLIST = 49
    SIID_PRINTERNET = 50
    SIID_SERVERSHARE = 51
    SIID_PRINTERFAX = 52
    SIID_PRINTERFAXNET = 53
    SIID_PRINTERFILE = 54
    SIID_STACK = 55
    SIID_MEDIASVCD = 56
    SIID_STUFFEDFOLDER = 57
    SIID_DRIVEUNKNOWN = 58
    SIID_DRIVEDVD = 59
    SIID_MEDIADVD = 60
    SIID_MEDIADVDRAM = 61
    SIID_MEDIADVDRW = 62
    SIID_MEDIADVDR = 63
    SIID_MEDIADVDROM = 64
    SIID_MEDIACDAUDIOPLUS = 65
    SIID_MEDIACDRW = 66
    SIID_MEDIACDR = 67
    SIID_MEDIACDBURN = 68
    SIID_MEDIABLANKCD = 69
    SIID_MEDIACDROM = 70
    SIID_AUDIOFILES = 71
    SIID_IMAGEFILES = 72
    SIID_VIDEOFILES = 73
    SIID_MIXEDFILES = 74
    SIID_FOLDERBACK = 75
    SIID_FOLDERFRONT = 76
    SIID_SHIELD = 77
    SIID_WARNING = 78
    SIID_INFO = 79
    SIID_ERROR = 80
    SIID_KEY = 81
    SIID_SOFTWARE = 82
    SIID_RENAME = 83
    SIID_DELETE = 84
    SIID_MEDIAAUDIODVD = 85
    SIID_MEDIAMOVIEDVD = 86
    SIID_MEDIAENHANCEDCD = 87
    SIID_MEDIAENHANCEDDVD = 88
    SIID_MEDIAHDDVD = 89
    SIID_MEDIABLURAY = 90
    SIID_MEDIAVCD = 91
    SIID_MEDIADVDPLUSR = 92
    SIID_MEDIADVDPLUSRW = 93
    SIID_DESKTOPPC = 94
    SIID_MOBILEPC = 95
    SIID_USERS = 96
    SIID_MEDIASMARTMEDIA = 97
    SIID_MEDIACOMPACTFLASH = 98
    SIID_DEVICECELLPHONE = 99
    SIID_DEVICECAMERA = 100
    SIID_DEVICEVIDEOCAMERA = 101
    SIID_DEVICEAUDIOPLAYER = 102
    SIID_NETWORKCONNECT = 103
    SIID_INTERNET = 104
    SIID_ZIPFILE = 105
    SIID_SETTINGS = 106
    SIID_DRIVEHDDVD = 132
    SIID_DRIVEBD = 133
    SIID_MEDIAHDDVDROM = 134
    SIID_MEDIAHDDVDR = 135
    SIID_MEDIAHDDVDRAM = 136
    SIID_MEDIABDROM = 137
    SIID_MEDIABDR = 138
    SIID_MEDIABDRE = 139
    SIID_CLUSTEREDDRIVE = 140
    SIID_MAX_ICONS = 181

    class SHSTOCKICONID(enum.IntFlag):
        SIID_DOCNOASSOC = 0
        SIID_DOCASSOC = 1
        SIID_APPLICATION = 2
        SIID_FOLDER = 3
        SIID_FOLDEROPEN = 4
        SIID_DRIVE525 = 5
        SIID_DRIVE35 = 6
        SIID_DRIVEREMOVE = 7
        SIID_DRIVEFIXED = 8
        SIID_DRIVENET = 9
        SIID_DRIVENETDISABLED = 10
        SIID_DRIVECD = 11
        SIID_DRIVERAM = 12
        SIID_WORLD = 13
        SIID_SERVER = 15
        SIID_PRINTER = 16
        SIID_MYNETWORK = 17
        SIID_FIND = 22
        SIID_HELP = 23
        SIID_SHARE = 28
        SIID_LINK = 29
        SIID_SLOWFILE = 30
        SIID_RECYCLER = 31
        SIID_RECYCLERFULL = 32
        SIID_MEDIACDAUDIO = 40
        SIID_LOCK = 47
        SIID_AUTOLIST = 49
        SIID_PRINTERNET = 50
        SIID_SERVERSHARE = 51
        SIID_PRINTERFAX = 52
        SIID_PRINTERFAXNET = 53
        SIID_PRINTERFILE = 54
        SIID_STACK = 55
        SIID_MEDIASVCD = 56
        SIID_STUFFEDFOLDER = 57
        SIID_DRIVEUNKNOWN = 58
        SIID_DRIVEDVD = 59
        SIID_MEDIADVD = 60
        SIID_MEDIADVDRAM = 61
        SIID_MEDIADVDRW = 62
        SIID_MEDIADVDR = 63
        SIID_MEDIADVDROM = 64
        SIID_MEDIACDAUDIOPLUS = 65
        SIID_MEDIACDRW = 66
        SIID_MEDIACDR = 67
        SIID_MEDIACDBURN = 68
        SIID_MEDIABLANKCD = 69
        SIID_MEDIACDROM = 70
        SIID_AUDIOFILES = 71
        SIID_IMAGEFILES = 72
        SIID_VIDEOFILES = 73
        SIID_MIXEDFILES = 74
        SIID_FOLDERBACK = 75
        SIID_FOLDERFRONT = 76
        SIID_SHIELD = 77
        SIID_WARNING = 78
        SIID_INFO = 79
        SIID_ERROR = 80
        SIID_KEY = 81
        SIID_SOFTWARE = 82
        SIID_RENAME = 83
        SIID_DELETE = 84
        SIID_MEDIAAUDIODVD = 85
        SIID_MEDIAMOVIEDVD = 86
        SIID_MEDIAENHANCEDCD = 87
        SIID_MEDIAENHANCEDDVD = 88
        SIID_MEDIAHDDVD = 89
        SIID_MEDIABLURAY = 90
        SIID_MEDIAVCD = 91
        SIID_MEDIADVDPLUSR = 92
        SIID_MEDIADVDPLUSRW = 93
        SIID_DESKTOPPC = 94
        SIID_MOBILEPC = 95
        SIID_USERS = 96
        SIID_MEDIASMARTMEDIA = 97
        SIID_MEDIACOMPACTFLASH = 98
        SIID_DEVICECELLPHONE = 99
        SIID_DEVICECAMERA = 100
        SIID_DEVICEVIDEOCAMERA = 101
        SIID_DEVICEAUDIOPLAYER = 102
        SIID_NETWORKCONNECT = 103
        SIID_INTERNET = 104
        SIID_ZIPFILE = 105
        SIID_SETTINGS = 106
        SIID_DRIVEHDDVD = 132
        SIID_DRIVEBD = 133
        SIID_MEDIAHDDVDROM = 134
        SIID_MEDIAHDDVDR = 135
        SIID_MEDIAHDDVDRAM = 136
        SIID_MEDIABDROM = 137
        SIID_MEDIABDR = 138
        SIID_MEDIABDRE = 139
        SIID_CLUSTEREDDRIVE = 140
        SIID_MAX_ICONS = 175

SHGNLI_PIDL = 0x000000001
SHGNLI_PREFIXNAME = 0x000000002
SHGNLI_NOUNIQUE = 0x000000004
SHGNLI_NOLNK = 0x000000008
if _WIN32_IE >= 0x0600:
    SHGNLI_NOLOCNAME = 0x000000010

if NTDDI_VERSION >= 0x06010000:
    SHGNLI_USEURLEXT = 0x000000020

PRINTACTION_OPEN = 0
PRINTACTION_PROPERTIES = 1
PRINTACTION_NETINSTALL = 2
PRINTACTION_NETINSTALLLINK = 3
PRINTACTION_TESTPAGE = 4
PRINTACTION_OPENNETPRN = 5
PRINTACTION_DOCUMENTDEFAULTS = 6
PRINTACTION_SERVERPROPERTIES = 7

class _OPEN_PRINTER_PROPS_INFOA(Structure):
    _fields_ = [('dwSize', DWORD),
                ('pszSheetName', LPSTR),
                ('uSheetIndex', UINT),
                ('dwFlags', DWORD),
                ('bModal', WINBOOL),
    ]

OPEN_PRINTER_PROPS_INFOA = _OPEN_PRINTER_PROPS_INFOA
POPEN_PRINTER_PROPS_INFOA = POINTER(OPEN_PRINTER_PROPS_INFOA)

class _OPEN_PRINTER_PROPS_INFOW(Structure):
    _fields_ = [('dwSize', DWORD),
                ('pszSheetName', LPWSTR),
                ('uSheetIndex', UINT),
                ('dwFlags', DWORD),
                ('bModal', WINBOOL),
    ]

OPEN_PRINTER_PROPS_INFOW = _OPEN_PRINTER_PROPS_INFOW
POPEN_PRINTER_PROPS_INFOW = POINTER(OPEN_PRINTER_PROPS_INFOW)

OFFLINE_STATUS_LOCAL = 0x0001
OFFLINE_STATUS_REMOTE = 0x0002
OFFLINE_STATUS_INCOMPLETE = 0x0004

if _WIN32_IE >= 0x0600:
    SHIL_LARGE = 0
    SHIL_SMALL = 1
    SHIL_EXTRALARGE = 2
    SHIL_SYSSMALL = 3
    if NTDDI_VERSION >= 0x06000000:
        SHIL_JUMBO = 4
        SHIL_LAST = SHIL_JUMBO
    else:
        SHIL_LAST = SHIL_SYSSMALL

if NTDDI_VERSION >= 0x06000000:
    WC_NETADDRESS = "msctls_netaddress"

    NCM_GETADDRESS =  (WM_USER+1)

    SNDMSG = SendMessage


    def NetAddr_GetAddress(hwnd: int, pv: int) -> int:
        return HRESULT(SNDMSG(hwnd, NCM_GETADDRESS, 0, LPARAM(pv).value)).value


    class tagNC_ADDRESS(Structure):
        class NET_ADDRESS_INFO_(Structure):
            pass

        _fields_ = [('pAddrInfo', POINTER(NET_ADDRESS_INFO_)),
                    ('PortNumber', USHORT),
                    ('PrefixLength', BYTE),
        ]

    NCM_SETALLOWTYPE =  (WM_USER+2)


    def NetAddr_SetAllowType(hwnd: int, addrMask: int) -> int:
        return HRESULT(SNDMSG(hwnd, NCM_SETALLOWTYPE, WPARAM(addrMask).value, 0)).value


    NCM_GETALLOWTYPE =  (WM_USER+3)


    def NetAddr_GetAllowType(hwnd: int) -> int:
        return DWORD(SNDMSG(hwnd, NCM_GETALLOWTYPE, 0, 0)).value


    NCM_DISPLAYERRORTIP =  (WM_USER+4)


    def NetAddr_DisplayErrorTip(hwnd: int) -> int:
        return HRESULT(SNDMSG(hwnd, NCM_DISPLAYERRORTIP, 0, 0)).value


def ShellExecute(hwnd: int = HWND(),
                 lpOperation: str = '',
                 lpFile: str = '',
                 lpParameters: str = '',
                 lpDirectory: str = '',
                 nShowCmd: int = SW_NORMAL,
                 unicode: bool = True) -> None:
    
    ShellExecute = (shell32.ShellExecuteW 
                    if unicode else shell32.ShellExecuteA
    )

    result = ShellExecute(hwnd, 
                          lpOperation, 
                          lpFile, 
                          lpParameters, 
                          lpDirectory, 
                          nShowCmd
    )
    
    if result <= 32:
        raise WinError(GetLastError())
    

def ShellExecuteEx(fMask: int = SEE_MASK_FLAG_NO_UI | SEE_MASK_FORCENOIDLIST, 
                   hwnd: int = HWND(), 
                   lpVerb: str = '', 
                   lpFile: str = '', 
                   lpParameters: str = '', 
                   lpDirectory: str = '', 
                   nShow: int = SW_NORMAL, 
                   hInstApp: Any = HINSTANCE(), 
                   lpIDList: int = VOID(), 
                   lpClass: str = '', 
                   hkeyClass: Any = HKEY(), 
                   dwHotKey: int = DWORD(), 
                   hIcon_Monitor: tuple = (None, None), 
                   unicode: bool = True) -> (int | None):
    
    ShellExecuteEx = (shell32.ShellExecuteExW 
                      if unicode else shell32.ShellExecuteExA
    )

    mbr = SHELLEXECUTEINFOW() if unicode else SHELLEXECUTEINFOA()
    mbr.cbSize = ctypes.sizeof(mbr)
    mbr.fMask = fMask
    mbr.hwnd = hwnd
    mbr.lpVerb = lpVerb
    mbr.lpFile = lpFile
    mbr.lpParameters = lpParameters
    mbr.lpDirectory = lpDirectory
    mbr.nShow = nShow
    mbr.lpIDList = lpIDList
    mbr.lpClass = lpClass
    mbr.hkeyClass = hkeyClass
    mbr.dwHotKey = dwHotKey
    mbr.hIcon_Monitor = SHELLEXECUTEICON(*hIcon_Monitor)
    res = ShellExecuteEx(ctypes.byref(mbr))
    hProcess = mbr.hProcess
    hInstApp = mbr.hInstApp

    if hInstApp is not None and hInstApp <= 32:
        raise WinError(GetLastError()) 
    
    if not res:
        raise WinError(GetLastError()) 
    
    return hProcess


def OpenProcess(dwDesiredAccess: int, 
                bInheritHandle: bool, 
                dwProcessId: int) -> int:
    
    OpenProcess = Kernel32.OpenProcess
    handle = OpenProcess(dwDesiredAccess, 
                        bInheritHandle, 
                        dwProcessId
    )

    if handle == NULL:
        raise WinError(GetLastError())
    return handle


def CloseHandle(hObject: int) -> None:
    CloseHandle = Kernel32.CloseHandle
    CloseHandle.argtypes = [HANDLE]
    CloseHandle.restype = BOOL
    result = CloseHandle(hObject)
    if result == NULL:
        raise WinError(GetLastError())


def QueryFullProcessImageName(hProcess: int, 
                              dwFlags: int, 
                              lpExeName: Any,
                              lpdwSize: Any,
                              unicode: bool = True) -> str:
    
    QueryFullProcessImageName = (Kernel32.QueryFullProcessImageNameW 
                                 if unicode else Kernel32.QueryFullProcessImageNameA
    )
    
    error_code = QueryFullProcessImageName(hProcess, dwFlags, lpExeName, lpdwSize)
    if error_code == NULL:
        raise WinError(GetLastError())


def ShellAbout(hwnd: int, 
               szApp: str, 
               szOtherStuff: str, 
               hIcon: int, 
               unicode: bool = True) -> None:
    
    ShellAbout = (shell32.ShellAboutW 
                  if unicode else shell32.ShellAboutA
    )

    res = ShellAbout(hwnd, szApp, szOtherStuff, hIcon)
    if not res:
        raise WinError(GetLastError())
    
