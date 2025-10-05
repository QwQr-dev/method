# coding = 'utf-8'
# shlobj.h

import enum
from ctypes import *
from typing import Any

try:
    from winerror import *
    from sdkddkver import *
    from public_dll import *
    from win_cbasictypes import *
    from error import GetLastError
    from wingdi import LF_FACESIZE
except ImportError:
    from .winerror import *
    from .sdkddkver import *
    from .public_dll import *
    from .win_cbasictypes import *
    from .error import GetLastError
    from .wingdi import LF_FACESIZE

WINBOOL = BOOL
_WIN32_IE = WIN32_IE

#############################################################
# from shtypes.h

class _SHITEMID(Structure):
    _fields_ = [('cb', USHORT),
                ('abID', BYTE * 1)
    ]

SHITEMID = _SHITEMID
LPSHITEMID = POINTER(SHITEMID)
LPCSHITEMID = LPSHITEMID

class _ITEMIDLIST(Structure):
    _fields_ = [('mkid', SHITEMID)]

ITEMIDLIST = _ITEMIDLIST

ITEMIDLIST_RELATIVE = ITEMIDLIST
ITEMID_CHILD = ITEMIDLIST
ITEMIDLIST_ABSOLUTE = ITEMIDLIST

LPITEMIDLIST = POINTER(ITEMIDLIST)
LPCITEMIDLIST = LPITEMIDLIST

PIDLIST_ABSOLUTE         = LPITEMIDLIST
PCIDLIST_ABSOLUTE        = LPCITEMIDLIST
PCUIDLIST_ABSOLUTE       = LPCITEMIDLIST
PIDLIST_RELATIVE         = LPITEMIDLIST
PCIDLIST_RELATIVE        = LPCITEMIDLIST
PUIDLIST_RELATIVE        = LPITEMIDLIST
PCUIDLIST_RELATIVE       = LPCITEMIDLIST
PITEMID_CHILD            = LPITEMIDLIST
PCITEMID_CHILD           = LPCITEMIDLIST
PUITEMID_CHILD           = LPITEMIDLIST
PCUITEMID_CHILD          = LPCITEMIDLIST
PCUITEMID_CHILD_ARRAY    = (LPCITEMIDLIST)
PCUIDLIST_RELATIVE_ARRAY = (LPCITEMIDLIST)
PCIDLIST_ABSOLUTE_ARRAY  = (LPCITEMIDLIST)
PCUIDLIST_ABSOLUTE_ARRAY = (LPCITEMIDLIST)

#############################################################
CSIDL_FLAG_CREATE = 0x8000

CSIDL_PERSONAL = 0x0005
CSIDL_MYPICTURES = 0x0027

CSIDL_APPDATA = 0x001a
CSIDL_MYMUSIC = 0x000d
CSIDL_MYVIDEO = 0x000e

SHGFP_TYPE_CURRENT = 0
SHGFP_TYPE_DEFAULT = 1

def SHGetMalloc(ppMalloc: Any):
    SHGetMalloc = shell32.SHGetMalloc
    res = SHGetMalloc(ppMalloc)
    if res:
        raise WinError(res)


def SHAlloc(cb: int) -> int:
    SHAlloc = shell32.SHAlloc
    return SHAlloc(cb)


def SHFree(pv: Any) -> None:
    SHFree = shell32.SHFree
    SHFree(pv)


GIL_OPENICON = 0x1
GIL_FORSHELL = 0x2
GIL_ASYNC = 0x20
GIL_DEFAULTICON = 0x40
GIL_FORSHORTCUT = 0x80
GIL_CHECKSHIELD = 0x200

GIL_SIMULATEDOC = 0x1
GIL_PERINSTANCE = 0x2
GIL_PERCLASS = 0x4
GIL_NOTFILENAME = 0x8
GIL_DONTCACHE = 0x10
GIL_SHIELD = 0x200
GIL_FORCENOSHIELD = 0x400

ISIOI_ICONFILE = 0x1
ISIOI_ICONINDEX = 0x2

SIOM_OVERLAYINDEX = 1
SIOM_ICONINDEX = 2

SIOM_RESERVED_SHARED = 0
SIOM_RESERVED_LINK = 1
SIOM_RESERVED_SLOWFILE = 2
SIOM_RESERVED_DEFAULT = 3

OI_DEFAULT = 0x0
OI_ASYNC = 0xffffeeee

IDO_SHGIOI_SHARE = 0x0fffffff
IDO_SHGIOI_LINK = 0x0ffffffe
IDO_SHGIOI_SLOWFILE = 0x0fffffffd
IDO_SHGIOI_DEFAULT = 0x0fffffffc

SLDF_DEFAULT = 0x00000000
SLDF_HAS_ID_LIST = 0x00000001
SLDF_HAS_LINK_INFO = 0x00000002
SLDF_HAS_NAME = 0x00000004
SLDF_HAS_RELPATH = 0x00000008
SLDF_HAS_WORKINGDIR = 0x00000010
SLDF_HAS_ARGS = 0x00000020
SLDF_HAS_ICONLOCATION = 0x00000040
SLDF_UNICODE = 0x00000080
SLDF_FORCE_NO_LINKINFO = 0x00000100
SLDF_HAS_EXP_SZ = 0x00000200
SLDF_RUN_IN_SEPARATE = 0x00000400

if NTDDI_VERSION < 0x06000000:
    SLDF_HAS_LOGO3ID = 0x00000800

SLDF_HAS_DARWINID = 0x00001000
SLDF_RUNAS_USER = 0x00002000
SLDF_HAS_EXP_ICON_SZ = 0x00004000
SLDF_NO_PIDL_ALIAS = 0x00008000
SLDF_FORCE_UNCNAME = 0x00010000
SLDF_RUN_WITH_SHIMLAYER = 0x00020000

if NTDDI_VERSION >= 0x06000000:
    SLDF_FORCE_NO_LINKTRACK = 0x00040000
    SLDF_ENABLE_TARGET_METADATA = 0x00080000
    SLDF_DISABLE_LINK_PATH_TRACKING = 0x00100000
    SLDF_DISABLE_KNOWNFOLDER_RELATIVE_TRACKING = 0x00200000

    if NTDDI_VERSION >= 0x06010000:
        SLDF_NO_KF_ALIAS = 0x00400000
        SLDF_ALLOW_LINK_TO_LINK = 0x00800000
        SLDF_UNALIAS_ON_SAVE = 0x01000000
        SLDF_PREFER_ENVIRONMENT_PATH = 0x02000000

        SLDF_KEEP_LOCAL_IDLIST_FOR_UNC_TARGET = 0x04000000

        if NTDDI_VERSION >= 0x06020000:
            SLDF_PERSIST_VOLUME_ID_RELATIVE = 0x08000000
            SLDF_VALID = 0x0ffff7ff
        else:
            SLDF_VALID = 0x07fff7ff
    else:
        SLDF_VALID = 0x003ff7ff
    SLDF_RESERVED = 0x80000000

class SHELL_LINK_DATA_FLAGS(enum.IntFlag):
    SLDF_DEFAULT = 0x00000000
    SLDF_HAS_ID_LIST = 0x00000001
    SLDF_HAS_LINK_INFO = 0x00000002
    SLDF_HAS_NAME = 0x00000004
    SLDF_HAS_RELPATH = 0x00000008
    SLDF_HAS_WORKINGDIR = 0x00000010
    SLDF_HAS_ARGS = 0x00000020
    SLDF_HAS_ICONLOCATION = 0x00000040
    SLDF_UNICODE = 0x00000080
    SLDF_FORCE_NO_LINKINFO = 0x00000100
    SLDF_HAS_EXP_SZ = 0x00000200
    SLDF_RUN_IN_SEPARATE = 0x00000400

    if NTDDI_VERSION < 0x06000000:
        SLDF_HAS_LOGO3ID = 0x00000800

    SLDF_HAS_DARWINID = 0x00001000
    SLDF_RUNAS_USER = 0x00002000
    SLDF_HAS_EXP_ICON_SZ = 0x00004000
    SLDF_NO_PIDL_ALIAS = 0x00008000
    SLDF_FORCE_UNCNAME = 0x00010000
    SLDF_RUN_WITH_SHIMLAYER = 0x00020000

    if NTDDI_VERSION >= 0x06000000:
        SLDF_FORCE_NO_LINKTRACK = 0x00040000
        SLDF_ENABLE_TARGET_METADATA = 0x00080000
        SLDF_DISABLE_LINK_PATH_TRACKING = 0x00100000
        SLDF_DISABLE_KNOWNFOLDER_RELATIVE_TRACKING = 0x00200000
    
        if NTDDI_VERSION >= 0x06010000:
            SLDF_NO_KF_ALIAS = 0x00400000
            SLDF_ALLOW_LINK_TO_LINK = 0x00800000
            SLDF_UNALIAS_ON_SAVE = 0x01000000
            SLDF_PREFER_ENVIRONMENT_PATH = 0x02000000

            SLDF_KEEP_LOCAL_IDLIST_FOR_UNC_TARGET = 0x04000000

            if NTDDI_VERSION >= 0x06020000:
                SLDF_PERSIST_VOLUME_ID_RELATIVE = 0x08000000
                SLDF_VALID = 0x0ffff7ff
            else:
                SLDF_VALID = 0x07fff7ff
        else:
            SLDF_VALID = 0x003ff7ff
        SLDF_RESERVED = 0x80000000

class tagDATABLOCKHEADER(Structure):
    _fields_ = [('cbSize', DWORD),
                ('dwSignature', DWORD)
    ]

DATABLOCK_HEADER = tagDATABLOCKHEADER
LPDATABLOCK_HEADER = POINTER(DATABLOCK_HEADER)
LPDBLIST = LPDATABLOCK_HEADER

class _COORD(Structure):    # from wincontypes.h
    _fields_ = [('X', SHORT),
                ('Y', SHORT)
    ]

COORD = _COORD
PCOORD = POINTER(COORD)

class NT_CONSOLE_PROPS(Structure):
    _fields_ = [('cbSize', DWORD),
                ('dwSignature', DWORD),
                ('wFillAttribute', WORD),
                ('wPopupFillAttribute', WORD),
                ('dwScreenBufferSize', COORD),
                ('dwWindowSize', COORD),
                ('dwWindowOrigin', COORD),
                ('nFont', DWORD),
                ('nInputBufferSize', DWORD),
                ('dwFontSize', COORD),
                ('uFontFamily', UINT),
                ('uFontWeight', UINT),
                ('FaceName', WCHAR * LF_FACESIZE),
                ('uCursorSize', UINT),
                ('bFullScreen', WINBOOL),
                ('bQuickEdit', WINBOOL),
                ('bInsertMode', WINBOOL),
                ('bAutoPosition', WINBOOL),
                ('uHistoryBufferSize', UINT),
                ('uNumberOfHistoryBuffers', UINT),
                ('bHistoryNoDup', WINBOOL),
                ('ColorTable', COLORREF * 16)
    ]

LPNT_CONSOLE_PROPS = POINTER(NT_CONSOLE_PROPS)

NT_CONSOLE_PROPS_SIG = 0xa0000002

class NT_FE_CONSOLE_PROPS(Structure):
    _fields_ = [('cbSize', DWORD),
                ('dwSignature', DWORD),
                ('uCodePage', UINT)
    ]

LPNT_FE_CONSOLE_PROPS = POINTER(NT_FE_CONSOLE_PROPS)

NT_FE_CONSOLE_PROPS_SIG = 0xa0000004

class EXP_DARWIN_LINK(Structure):
    _fields_ = [('cbSize', DWORD),
                ('dwSignature', DWORD),
                ('szDarwinID', CHAR * MAX_PATH),
                ('szwDarwinID', WCHAR * MAX_PATH),
    ]

LPEXP_DARWIN_LINK = POINTER(EXP_DARWIN_LINK)

EXP_DARWIN_ID_SIG = 0xa0000006

EXP_SPECIAL_FOLDER_SIG = 0xa0000005

class EXP_SPECIAL_FOLDER(Structure):
    _fields_ = [('cbSize', DWORD),
                ('dwSignature', DWORD),
                ('idSpecialFolder', DWORD),
                ('cbOffset', DWORD)
    ]

LPEXP_SPECIAL_FOLDER = POINTER(EXP_SPECIAL_FOLDER)

class EXP_SZ_LINK(Structure):
    _fields_ = [('cbSize', DWORD),
                ('dwSignature', DWORD),
                ('szTarget', CHAR * MAX_PATH),
                ('swzTarget', WCHAR * MAX_PATH)
    ]

LPEXP_SZ_LINK = POINTER(EXP_SZ_LINK)

EXP_SZ_LINK_SIG = 0xa0000001
EXP_SZ_ICON_SIG = 0xa0000007

if NTDDI_VERSION >= 0x06000000:
    class EXP_PROPERTYSTORAGE(Structure):
        _fields_ = [('cbSize', DWORD),
                    ('dwSignature', DWORD),
                    ('abPropertyStorage', BYTE * 1)
        ]

    EXP_PROPERTYSTORAGE_SIG = 0xa0000009

FCIDM_SHVIEWFIRST = 0x0000
FCIDM_SHVIEWLAST = 0x7fff
FCIDM_BROWSERFIRST = 0xa000
FCIDM_BROWSERLAST = 0xbf00
FCIDM_GLOBALFIRST = 0x8000
FCIDM_GLOBALLAST = 0x9fff

FCIDM_MENU_FILE = (FCIDM_GLOBALFIRST+0x0000)
FCIDM_MENU_EDIT = (FCIDM_GLOBALFIRST+0x0040)
FCIDM_MENU_VIEW = (FCIDM_GLOBALFIRST+0x0080)
FCIDM_MENU_VIEW_SEP_OPTIONS = (FCIDM_GLOBALFIRST+0x0081)
FCIDM_MENU_TOOLS = (FCIDM_GLOBALFIRST+0x00c0)
FCIDM_MENU_TOOLS_SEP_GOTO = (FCIDM_GLOBALFIRST+0x00c1)
FCIDM_MENU_HELP = (FCIDM_GLOBALFIRST+0x0100)
FCIDM_MENU_FIND = (FCIDM_GLOBALFIRST+0x0140)
FCIDM_MENU_EXPLORE = (FCIDM_GLOBALFIRST+0x0150)
FCIDM_MENU_FAVORITES = (FCIDM_GLOBALFIRST+0x0170)

FCIDM_TOOLBAR = (FCIDM_BROWSERFIRST + 0)
FCIDM_STATUS = (FCIDM_BROWSERFIRST + 1)

IDC_OFFLINE_HAND = 103

if WIN32_IE >= 0x0700:
    IDC_PANTOOL_HAND_OPEN = 104
    IDC_PANTOOL_HAND_CLOSED = 105

PANE_NONE = DWORD(-1).value
PANE_ZONE = 1
PANE_OFFLINE = 2
PANE_PRINTER = 3
PANE_SSL = 4
PANE_NAVIGATION = 5
PANE_PROGRESS = 6

if _WIN32_IE >= 0x0600:
    PANE_PRIVACY = 7


def ILClone(pidl: int) -> int:
    ILClone = shell32.ILClone
    return ILClone(pidl)


def ILCloneFirst(pidl: int) -> int:
    ILCloneFirst = shell32.ILCloneFirst
    return ILCloneFirst(pidl)


def ILCombine(pidl1: int, pidl2: int) -> int:
    ILCombine = shell32.ILCombine
    return ILCombine(pidl1, pidl2)


def ILFree(pidl: int) -> None:
    ILFree = shell32.ILFree
    ILFree.argtypes = [VOID]
    ILFree.restype = VOID
    ILFree(pidl)


def ILGetNext(pidl):
    ILGetNext = shell32.ILGetNext
    return ILGetNext(pidl)


def ILGetSize(pidl):
    ILGetSize = shell32.ILGetSize
    return ILGetSize(pidl)


def ILFindChild(pidlParent, pidlChild):
    ILFindChild = shell32.ILFindChild
    return ILFindChild(pidlParent, pidlChild)


def ILFindLastID(pidl: int) -> int:
    ILFindLastID = shell32.ILFindLastID
    res = ILFindLastID(pidl)
    return res


def ILRemoveLastID(pidl):
    ILRemoveLastID = shell32.ILRemoveLastID
    return ILRemoveLastID(pidl)


def ILIsEqual(pidl1, pidl2):
    ILIsEqual = shell32.ILIsEqual
    return ILIsEqual(pidl1, pidl2)


def ILIsParent(pidl1, pidl2):
    ILIsParent = shell32.ILIsParent
    return ILIsParent(pidl1, pidl2)


def ILSaveToStream(pstm, pidl):
    ILSaveToStream = shell32.ILSaveToStream
    res = ILSaveToStream(pstm, pidl)
    if res:
        raise WinError(res)


def ILLoadFromStream(pstm, pidl):
    ILLoadFromStream = shell32.ILLoadFromStream
    res = ILLoadFromStream(pstm, pidl)
    if res:
        raise WinError(res)


if NTDDI_VERSION >= 0x06000000:
    def ILLoadFromStreamEx(pstm, pidl):
        ILLoadFromStreamEx = shell32.ILLoadFromStreamEx
        res = ILLoadFromStreamEx(pstm, pidl)
        if res:
            raise WinError(res)


def ILCreateFromPath(pszPath: str, unicode: bool = True) -> int:
    ILCreateFromPath = (shell32.ILCreateFromPathW 
                        if unicode else shell32.ILCreateFromPathA
    )

    ILCreateFromPath.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    ILCreateFromPath.restype = VOID
    res = ILCreateFromPath(pszPath)
    return res


def SHILCreateFromPath(pszPath, ppidl, rgfInOut):
    SHILCreateFromPath = Kernel32.SHILCreateFromPath
    res = SHILCreateFromPath(pszPath, ppidl, rgfInOut)
    if res:
        raise WinError(res)
    

def VOID_OFFSET(pv, cb):
    return VOID(BYTE(pv).value + cb).value


ILCloneFull = ILClone
ILCloneChild = ILCloneFirst

def ILSkip(P, C):
    return PUIDLIST_RELATIVE(VOID_OFFSET(P, C))

def ILNext(P):
    temp_stru = PUIDLIST_RELATIVE()
    temp_stru.mkid.cb = P
    return temp_stru.mkid.cb

def ILIsAligned(P):
    return (DWORD_PTR(P).value & (sizeof(VOID()) - 1)) == 0

def ILIsEmpty(P):
    temp_stru = PUIDLIST_RELATIVE()
    temp_stru.mkid.cb = P
    return not P or temp_stru.mkid.cb == 0

def ILIsChild(P):
    return ILIsEmpty(P) or ILIsEmpty(ILNext(P))


def ILAppendID(pidl, pmkid, fAppend):
    ILAppendID = shell32.ILAppendID
    return ILAppendID(pidl, pmkid, fAppend)


if NTDDI_VERSION >= 0x06000000:
    GPFIDL_DEFAULT = 0x0
    GPFIDL_ALTNAME = 0x1
    GPFIDL_UNCPRINTER = 0x2

    class tagGPFIDL_FLAGS(enum.IntFlag):
        GPFIDL_DEFAULT = 0x0
        GPFIDL_ALTNAME = 0x1
        GPFIDL_UNCPRINTER = 0x2

    GPFIDL_FLAGS = INT

    def SHGetPathFromIDListEx(pidl, pszPath, cchPath, uOpts):
        SHGetPathFromIDListEx = shell32.SHGetPathFromIDListEx
        res = SHGetPathFromIDListEx(pidl, pszPath, cchPath, uOpts)
        if not res:
            raise WinError(GetLastError())
    

def SHGetPathFromIDList(pidl, pszPath, unicode: bool = True):
    SHGetPathFromIDList = (shell32.SHGetPathFromIDListW 
                           if unicode else shell32.SHGetPathFromIDListA
    )

    res = SHGetPathFromIDList(pidl, pszPath)
    if not res:
        raise WinError(GetLastError())


def SHCreateDirectory(hwnd, pszPath):
    SHCreateDirectory = shell32.SHCreateDirectory
    res = SHCreateDirectory(hwnd, pszPath)
    if res:
        raise WinError(res)


def SHCreateDirectoryEx(hwnd, pszPath, psa, unicode: bool = True):
    SHCreateDirectoryEx = (shell32.SHCreateDirectoryExW 
                           if unicode else shell32.SHCreateDirectoryExA
    )

    res = SHCreateDirectoryEx(hwnd, pszPath, psa)
    if res:
        raise WinError(res)


def SHOpenFolderAndSelectItems(pidlFolder: int, 
                               cidl: int, 
                               apidl: Any, 
                               dwFlags: int) -> None:
    
    SHOpenFolderAndSelectItems = shell32.SHOpenFolderAndSelectItems
    SHOpenFolderAndSelectItems.argtypes = [VOID, UINT, VOID, DWORD]
    SHOpenFolderAndSelectItems.restype = HRESULT
    res = SHOpenFolderAndSelectItems(pidlFolder, cidl, apidl, dwFlags)
    if res:
        raise WinError(res)
    

def SHCreateShellItem(pidlParent, psfParent, pidl, ppsi):
    SHCreateShellItem = shell32.SHCreateShellItem
    res = SHCreateShellItem(pidlParent, psfParent, pidl, ppsi)
    if res:
        raise WinError(res)


CSIDL_DESKTOP = 0x0000
CSIDL_INTERNET = 0x0001
CSIDL_PROGRAMS = 0x0002
CSIDL_CONTROLS = 0x0003
CSIDL_PRINTERS = 0x0004
CSIDL_FAVORITES = 0x0006
CSIDL_STARTUP = 0x0007
CSIDL_RECENT = 0x0008
CSIDL_SENDTO = 0x0009
CSIDL_BITBUCKET = 0x000a
CSIDL_STARTMENU = 0x000b
CSIDL_MYDOCUMENTS = CSIDL_PERSONAL
CSIDL_DESKTOPDIRECTORY = 0x0010
CSIDL_DRIVES = 0x0011
CSIDL_NETWORK = 0x0012
CSIDL_NETHOOD = 0x0013
CSIDL_FONTS = 0x0014
CSIDL_TEMPLATES = 0x0015
CSIDL_COMMON_STARTMENU = 0x0016
CSIDL_COMMON_PROGRAMS = 0x0017
CSIDL_COMMON_STARTUP = 0x0018
CSIDL_COMMON_DESKTOPDIRECTORY = 0x0019
CSIDL_PRINTHOOD = 0x001b

CSIDL_LOCAL_APPDATA = 0x001c

CSIDL_ALTSTARTUP = 0x001d
CSIDL_COMMON_ALTSTARTUP = 0x001e
CSIDL_COMMON_FAVORITES = 0x001f

CSIDL_INTERNET_CACHE = 0x0020
CSIDL_COOKIES = 0x0021
CSIDL_HISTORY = 0x0022
CSIDL_COMMON_APPDATA = 0x0023
CSIDL_WINDOWS = 0x0024
CSIDL_SYSTEM = 0x0025
CSIDL_PROGRAM_FILES = 0x0026

CSIDL_PROFILE = 0x0028
CSIDL_SYSTEMX86 = 0x0029
CSIDL_PROGRAM_FILESX86 = 0x002a

CSIDL_PROGRAM_FILES_COMMON = 0x002b

CSIDL_PROGRAM_FILES_COMMONX86 = 0x002c
CSIDL_COMMON_TEMPLATES = 0x002d

CSIDL_COMMON_DOCUMENTS = 0x002e
CSIDL_COMMON_ADMINTOOLS = 0x002f
CSIDL_ADMINTOOLS = 0x0030

CSIDL_CONNECTIONS = 0x0031
CSIDL_COMMON_MUSIC = 0x0035
CSIDL_COMMON_PICTURES = 0x0036
CSIDL_COMMON_VIDEO = 0x0037
CSIDL_RESOURCES = 0x0038

CSIDL_RESOURCES_LOCALIZED = 0x0039

CSIDL_COMMON_OEM_LINKS = 0x003a
CSIDL_CDBURN_AREA = 0x003b

CSIDL_COMPUTERSNEARME = 0x003d

CSIDL_FLAG_DONT_VERIFY = 0x4000
CSIDL_FLAG_DONT_UNEXPAND = 0x2000
CSIDL_FLAG_NO_ALIAS = 0x1000
CSIDL_FLAG_PER_USER_INIT = 0x0800
CSIDL_FLAG_MASK = 0xff00


def SHGetSpecialFolderLocation(hwnd, csidl, ppidl):
    SHGetSpecialFolderLocation = shell32.SHGetSpecialFolderLocation
    res = SHGetSpecialFolderLocation(hwnd, csidl, ppidl)
    if res:
        raise WinError(res)
    

def SHCloneSpecialIDList(hwnd, csidl, fCreate):
    SHCloneSpecialIDList = shell32.SHCloneSpecialIDList
    return SHCloneSpecialIDList(hwnd, csidl, fCreate)


def SHGetSpecialFolderPath(hwnd, pszPath, csidl, fCreate, unicode: bool = True):
    SHGetSpecialFolderPath = shell32.SHGetSpecialFolderPathW if unicode else shell32.SHGetSpecialFolderPathA
    res = SHGetSpecialFolderPath(hwnd, pszPath, csidl, fCreate)
    if not res:
        raise WinError(GetLastError())


def SHFlushSFCache():
    SHFlushSFCache = shell32.SHFlushSFCache
    return SHFlushSFCache()


def SHGetFolderPath(hwnd: int, 
                    csidl: int, 
                    hToken: int, 
                    dwFlags: int, 
                    pszPath: Any, 
                    unicode: bool = True) -> None:
    
    SHGetFolderPath = (shell32.SHGetFolderPathW 
                       if unicode else shell32.SHGetFolderPathA
    )

    res = SHGetFolderPath(hwnd, csidl, hToken, dwFlags, pszPath)
    if res:
        raise WinError(res)


def SHSetFolderPath(csidl, hToken, dwFlags, pszPath, unicode: bool = True):
    SHSetFolderPath = shell32.SHSetFolderPathW if unicode else shell32.SHSetFolderPathA
    res = SHSetFolderPath(csidl, hToken, dwFlags, pszPath)
    if res:
        raise WinError(res)


def SHGetFolderLocation(hwnd, csidl, hToken, dwFlags, ppidl):
    SHGetFolderLocation = shell32.SHGetFolderLocation
    res = SHGetFolderLocation(hwnd, csidl, hToken, dwFlags, ppidl)
    if res:
        raise WinError(res)


def SHGetFolderPathAndSubDir(hwnd, csidl, hToken, dwFlags, pszSubDir, pszPath, unicode: bool = True):
    SHGetFolderPathAndSubDir = (shell32.SHGetFolderPathAndSubDirW 
                                if unicode else shell32.SHGetFolderPathAndSubDirA
    )
    
    res = SHGetFolderPathAndSubDir(hwnd, csidl, hToken, dwFlags, pszSubDir, pszPath)
    if res:
        raise WinError(res)
    

if NTDDI_VERSION >= 0x06000000:
    KF_FLAG_DEFAULT = 0x00000000
    if NTDDI_VERSION >= NTDDI_WIN10_RS3:
        KF_FLAG_FORCE_APP_DATA_REDIRECTION = 0x00080000

    if NTDDI_VERSION >= NTDDI_WIN10_RS2:
        KF_FLAG_RETURN_FILTER_REDIRECTION_TARGET = 0x00040000
        KF_FLAG_FORCE_PACKAGE_REDIRECTION = 0x00020000
        KF_FLAG_NO_PACKAGE_REDIRECTION = 0x00010000

    if NTDDI_VERSION >= NTDDI_WIN8:
        KF_FLAG_FORCE_APPCONTAINER_REDIRECTION = 0x00020000

    if NTDDI_VERSION >= 0x06010000:
        KF_FLAG_NO_APPCONTAINER_REDIRECTION = 0x00010000

    KF_FLAG_CREATE = 0x00008000
    KF_FLAG_DONT_VERIFY = 0x00004000
    KF_FLAG_DONT_UNEXPAND = 0x00002000
    KF_FLAG_NO_ALIAS = 0x00001000
    KF_FLAG_INIT = 0x00000800
    KF_FLAG_DEFAULT_PATH = 0x00000400
    KF_FLAG_NOT_PARENT_RELATIVE = 0x00000200
    KF_FLAG_SIMPLE_IDLIST = 0x00000100
    KF_FLAG_ALIAS_ONLY = 0x80000000

    class KNOWN_FOLDER_FLAG(enum.IntFlag):
        KF_FLAG_DEFAULT = 0x00000000
        if NTDDI_VERSION >= NTDDI_WIN10_RS3:
            KF_FLAG_FORCE_APP_DATA_REDIRECTION = 0x00080000
        
        if NTDDI_VERSION >= NTDDI_WIN10_RS2:
            KF_FLAG_RETURN_FILTER_REDIRECTION_TARGET = 0x00040000
            KF_FLAG_FORCE_PACKAGE_REDIRECTION = 0x00020000
            KF_FLAG_NO_PACKAGE_REDIRECTION = 0x00010000

        if NTDDI_VERSION >= NTDDI_WIN8:
            KF_FLAG_FORCE_APPCONTAINER_REDIRECTION = 0x00020000

        if NTDDI_VERSION >= 0x06010000:
            KF_FLAG_NO_APPCONTAINER_REDIRECTION = 0x00010000
        
        KF_FLAG_CREATE = 0x00008000
        KF_FLAG_DONT_VERIFY = 0x00004000
        KF_FLAG_DONT_UNEXPAND = 0x00002000
        KF_FLAG_NO_ALIAS = 0x00001000
        KF_FLAG_INIT = 0x00000800
        KF_FLAG_DEFAULT_PATH = 0x00000400
        KF_FLAG_NOT_PARENT_RELATIVE = 0x00000200
        KF_FLAG_SIMPLE_IDLIST = 0x00000100
        KF_FLAG_ALIAS_ONLY = 0x80000000

    def SHGetKnownFolderIDList(rfid, dwFlags, hToken, ppidl):
        SHGetKnownFolderIDList = shell32.SHGetKnownFolderIDList
        res = SHGetKnownFolderIDList(rfid, dwFlags, hToken, ppidl)
        if res:
            raise WinError(res)



    def SHSetKnownFolderPath(rfid, dwFlags, hToken, pszPath):
        SHSetKnownFolderPath = shell32.SHSetKnownFolderPath
        res = SHSetKnownFolderPath(rfid, dwFlags, hToken, pszPath)
        if res:
            raise WinError(res)
        

    def SHGetKnownFolderPath(rfid: Any, dwFlags: int, hToken: int, ppszPath: Any):
        SHGetKnownFolderPath = shell32.SHGetKnownFolderPath
        res = SHGetKnownFolderPath(rfid, dwFlags, hToken, ppszPath)
        if res:
            raise WinError(res)
        

if NTDDI_VERSION >= 0x06010000:
    def SHGetKnownFolderItem(rfid, flags, hToken, riid, ppv):
        SHGetKnownFolderItem = shell32.SHGetKnownFolderItem
        res = SHGetKnownFolderItem(rfid, flags, hToken, riid, ppv)
        if res:
            raise WinError(res)
    

FCS_READ = 0x00000001
FCS_FORCEWRITE = 0x00000002
FCS_WRITE = (FCS_READ | FCS_FORCEWRITE)

FCS_FLAG_DRAGDROP = 2

FCSM_VIEWID = 0x00000001
FCSM_WEBVIEWTEMPLATE = 0x00000002
FCSM_INFOTIP = 0x00000004
FCSM_CLSID = 0x00000008
FCSM_ICONFILE = 0x00000010
FCSM_LOGO = 0x00000020
FCSM_FLAGS = 0x00000040

