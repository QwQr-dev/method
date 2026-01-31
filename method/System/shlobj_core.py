# coding = 'utf-8'
# shlobj_core.h

from method.System.shiobj import *
from method.System.winuser import *
from method.System.sdkddkver import *
from method.System.public_dll import *
from method.System.winusutypes import *

_WIN32_WINNT = WIN32_WINNT

BIF_RETURNONLYFSDIRS =     0x00000001   # For finding a folder to start document searching
BIF_DONTGOBELOWDOMAIN =    0x00000002   # For starting the Find Computer
BIF_STATUSTEXT =           0x00000004   # Top of the dialog has 2 lines of text for BROWSEINFO.lpszTitle and one line if
                                        # this flag is set.  Passing the message BFFM_SETSTATUSTEXTA to the hwnd can set the
                                        # rest of the text.  This is not used with BIF_USENEWUI and BROWSEINFO.lpszTitle gets
                                        # all three lines of text.
BIF_RETURNFSANCESTORS =    0x00000008
BIF_EDITBOX =              0x00000010   # Add an editbox to the dialog
BIF_VALIDATE =             0x00000020   # insist on valid result (or CANCEL)

BIF_NEWDIALOGSTYLE =       0x00000040   # Use the new dialog layout with the ability to resize
                                        # Caller needs to call OleInitialize() before using this API

BIF_USENEWUI =             (BIF_NEWDIALOGSTYLE | BIF_EDITBOX)

BIF_BROWSEINCLUDEURLS =    0x00000080   # Allow URLs to be displayed or entered. (Requires BIF_USENEWUI)
BIF_UAHINT =               0x00000100   # Add a UA hint to the dialog, in place of the edit box. May not be combined with BIF_EDITBOX
BIF_NONEWFOLDERBUTTON =    0x00000200   # Do not add the "New Folder" button to the dialog.  Only applicable with BIF_NEWDIALOGSTYLE.
BIF_NOTRANSLATETARGETS =   0x00000400   # don't traverse target as shortcut

BIF_BROWSEFORCOMPUTER =    0x00001000  # Browsing for Computers.
BIF_BROWSEFORPRINTER =     0x00002000  # Browsing for Printers
BIF_BROWSEINCLUDEFILES =   0x00004000  # Browsing for Everything
BIF_SHAREABLE =            0x00008000  # sharable resources displayed (remote shares, requires BIF_USENEWUI)
BIF_BROWSEFILEJUNCTIONS =  0x00010000  # allow folder junctions like zip files and libraries to be browsed

# message from browser
BFFM_INITIALIZED =         1
BFFM_SELCHANGED =          2
BFFM_VALIDATEFAILEDA =     3   # lParam:szPath ret:1(cont),0(EndDialog)
BFFM_VALIDATEFAILEDW =     4   # lParam:wzPath ret:1(cont),0(EndDialog)
BFFM_IUNKNOWN =            5   # provides IUnknown to client. lParam: IUnknown*

# messages to browser
BFFM_SETSTATUSTEXTA =      (WM_USER + 100)
BFFM_ENABLEOK =            (WM_USER + 101)
BFFM_SETSELECTIONA =       (WM_USER + 102)
BFFM_SETSELECTIONW =       (WM_USER + 103)
BFFM_SETSTATUSTEXTW =      (WM_USER + 104)
BFFM_SETOKTEXT =           (WM_USER + 105) # Unicode only
BFFM_SETEXPANDED =         (WM_USER + 106) # Unicode only

OFN_READONLY =                 0x00000001
OFN_OVERWRITEPROMPT =          0x00000002
OFN_HIDEREADONLY =             0x00000004
OFN_NOCHANGEDIR =              0x00000008
OFN_SHOWHELP =                 0x00000010
OFN_ENABLEHOOK =               0x00000020
OFN_ENABLETEMPLATE =           0x00000040
OFN_ENABLETEMPLATEHANDLE =     0x00000080
OFN_NOVALIDATE =               0x00000100
OFN_ALLOWMULTISELECT =         0x00000200
OFN_EXTENSIONDIFFERENT =       0x00000400
OFN_PATHMUSTEXIST =            0x00000800
OFN_FILEMUSTEXIST =            0x00001000
OFN_CREATEPROMPT =             0x00002000
OFN_SHAREAWARE =               0x00004000
OFN_NOREADONLYRETURN =         0x00008000
OFN_NOTESTFILECREATE =         0x00010000
OFN_NONETWORKBUTTON =          0x00020000
OFN_NOLONGNAMES =              0x00040000     # force no long names for 4.x modules

if WINVER >= 0x0400:
    OFN_EXPLORER =                 0x00080000     # new look commdlg
    OFN_NODEREFERENCELINKS =       0x00100000
    OFN_LONGNAMES =                0x00200000     # force long names for 3.x modules
    # OFN_ENABLEINCLUDENOTIFY and OFN_ENABLESIZING require
    # Windows 2000 or higher to have any effect.
    OFN_ENABLEINCLUDENOTIFY =      0x00400000     # send include message to callback
    OFN_ENABLESIZING =             0x00800000

if (_WIN32_WINNT >= 0x0500):
    OFN_DONTADDTORECENT =          0x02000000
    OFN_FORCESHOWHIDDEN =          0x10000000    # Show All files including System and hidden files

#FlagsEx Values
if (_WIN32_WINNT >= 0x0500):
    OFN_EX_NOPLACESBAR =         0x00000001

# Return values for the registered message sent to the hook function
# when a sharing violation occurs.  OFN_SHAREFALLTHROUGH allows the
# filename to be accepted, OFN_SHARENOWARN rejects the name but puts
# up no warning (returned when the app has already put up a warning
# message), and OFN_SHAREWARN puts up the default warning message
# for sharing violations.
#
# Note:  Undefined return values map to OFN_SHAREWARN, but are
#        reserved for future use.

OFN_SHAREFALLTHROUGH =     2
OFN_SHARENOWARN =          1
OFN_SHAREWARN =            0


LPOFNHOOKPROC = CALLBACK(UINT_PTR, HWND, UINT, WPARAM, LPARAM)
BFFCALLBACK = CALLBACK(INT, HWND, UINT, LPARAM, LPARAM)

class tagEDITMENU(Structure):
    _fields_ = [('hmenu', HMENU),
                ('idEdit', WORD),
                ('idCut', WORD),
                ('idCopy', WORD),
                ('idPaste', WORD),
                ('idClear', WORD),
                ('idUndo', WORD)
    ]

EDITMENU = tagEDITMENU
LPEDITMENU = POINTER(EDITMENU)

class tagOFNA(Structure):
    _fields_ = [('lStructSize', DWORD),
                ('hwndOwner', HWND),
                ('hInstance', HINSTANCE),
                ('lpstrFilter', LPCSTR),
                ('lpstrCustomFilter', LPSTR),
                ('nMaxCustFilter', DWORD),
                ('nFilterIndex', DWORD),
                ('lpstrFile', LPSTR),
                ('nMaxFile', DWORD),
                ('lpstrFileTitle', LPSTR),
                ('nMaxFileTitle', DWORD),
                ('lpstrInitialDir', LPCSTR),
                ('lpstrTitle', LPCSTR),
                ('Flags', DWORD),
                ('nFileOffset', WORD),
                ('nFileExtension', WORD),
                ('lpstrDefExt', LPCSTR),
                ('lCustData', LPARAM),
                ('lpfnHook', LPOFNHOOKPROC),
                ('lpTemplateName', LPCSTR),
                # ('lpEditInfo', LPEDITMENU),
                # ('lpstrPrompt', LPCWSTR),         
    ]

    if WIN32_WINNT >= 0x0500:
        _fields_.append(('pvReserved', PVOID))
        _fields_.append(('dwReserved', DWORD))
        _fields_.append(('FlagsEx', DWORD))

OPENFILENAMEA = tagOFNA
LPOPENFILENAMEA = POINTER(OPENFILENAMEA)

class tagOFNW(Structure):
    _fields_ = [('lStructSize', DWORD),
                ('hwndOwner', HWND),
                ('hInstance', HINSTANCE),
                ('lpstrFilter', LPCWSTR),
                ('lpstrCustomFilter', LPWSTR),
                ('nMaxCustFilter', DWORD),
                ('nFilterIndex', DWORD),
                ('lpstrFile', LPWSTR),
                ('nMaxFile', DWORD),
                ('lpstrFileTitle', LPWSTR),
                ('nMaxFileTitle', DWORD),
                ('lpstrInitialDir', LPCWSTR),
                ('lpstrTitle', LPCWSTR),
                ('Flags', DWORD),
                ('nFileOffset', WORD),
                ('nFileExtension', WORD),
                ('lpstrDefExt', LPCWSTR),
                ('lCustData', LPARAM),
                ('lpfnHook', LPOFNHOOKPROC),
                ('lpTemplateName', LPCWSTR),
                # ('lpEditInfo', LPEDITMENU),
                # ('lpstrPrompt', LPCWSTR), 
    ]

    if WIN32_WINNT >= 0x0500:
        _fields_.append(('pvReserved', PVOID))
        _fields_.append(('dwReserved', DWORD))
        _fields_.append(('FlagsEx', DWORD))


OPENFILENAMEW = tagOFNW
LPOPENFILENAMEW = POINTER(OPENFILENAMEW)

PCIDLIST_ABSOLUT = LPCITEMIDLIST

class _browseinfoA(Structure):
    _fields_ = [('hwndOwner', HWND),
                ('pidlRoot', PCIDLIST_ABSOLUT),
                ('pszDisplayName', LPSTR),
                ('lpszTitle', LPCSTR),
                ('ulFlags', UINT),
                ('lpfn', BFFCALLBACK),
                ('lParam', LPARAM),
                ('iImage', INT)
    ]

BROWSEINFOA = _browseinfoA
PBROWSEINFOA = POINTER(BROWSEINFOA)
LPBROWSEINFOA = PBROWSEINFOA

class _browseinfoW(Structure):
    _fields_ = [('hwndOwner', HWND),
                ('pidlRoot', PCIDLIST_ABSOLUT),
                ('pszDisplayName', LPWSTR),
                ('lpszTitle', LPCWSTR),
                ('ulFlags', UINT),
                ('lpfn', BFFCALLBACK),
                ('lParam', LPARAM),
                ('iImage', INT)
    ]

BROWSEINFOW = _browseinfoW
PBROWSEINFOW = POINTER(BROWSEINFOW)
LPBROWSEINFOW = PBROWSEINFOW


def SHBrowseForFolder(lpbi, unicode: bool = True):
    SHBrowseForFolder = (shell32.SHBrowseForFolderW 
                         if unicode else shell32.SHBrowseForFolderA
    )

    SHBrowseForFolder.argtypes = [POINTER(BROWSEINFOW) if unicode else POINTER(BROWSEINFOA)]
    SHBrowseForFolder.restype = VOID
    return SHBrowseForFolder(lpbi)


def SHGetPathFromIDList(pidl, pszPath, unicode: bool = True, errcheck: bool = True):
    SHGetPathFromIDList = (shell32.SHGetPathFromIDListW 
                           if unicode else shell32.SHGetPathFromIDListA
    )

    SHGetPathFromIDList.argtypes = [VOID, 
                                    (LPWSTR if unicode else LPSTR)
    ]
    
    SHGetPathFromIDList.restype = BOOL
    res = SHGetPathFromIDList(pidl, pszPath)
    return win32_to_errcheck(res, errcheck)
