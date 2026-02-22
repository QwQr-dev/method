# coding = 'utf-8'

import os
import sys
from method.System.winusutypes import *
from method.System.sdkddkver import WIN64
from method.System import shiobj, knownfolders
from method.System.wow64apiset import GetSystemWow64Directory
from method.System.sysinfoapi import GetSystemDirectory, GetWindowsDirectory


def _SYSTEM32() -> str:
    path = (WCHAR * MAX_PATH)()
    GetSystemDirectory(path, MAX_PATH)
    return path.value


def _SYSWOW64() -> (str | None):
    wow64_path = (WCHAR * MAX_PATH)()
    try:
        GetSystemWow64Directory(wow64_path, MAX_PATH)
    except:
        return None
    return wow64_path.value


def _WINDOWS() -> str:
    path = (WCHAR * MAX_PATH)()
    GetWindowsDirectory(path, MAX_PATH)
    return path.value


WINDOWS: str = _WINDOWS()
SYSTEMROOT: str = _WINDOWS()
SYSTEM32: str = _SYSTEM32()
SYSWOW64 = _SYSWOW64()  
APPDATA: str = os.environ['APPDATA']
HOMEDRIVE: str = os.environ['HOMEDRIVE']
HOMEPATH: str = os.environ['HOMEPATH']
LOCALAPPDATA: str = os.environ['LOCALAPPDATA']

try:
    LOGONSERVER = os.environ['LOGONSERVER']
    USERDOMAIN_ROAMINGPROFILE = os.environ['USERDOMAIN_ROAMINGPROFILE']        
except:
    LOGONSERVER = None
    USERDOMAIN_ROAMINGPROFILE = None

USERDOMAIN: str = os.environ['USERDOMAIN']
USERNAME: str = os.environ['USERNAME']
USERPROFILE: str = os.environ['USERPROFILE']
HOME: str = HOMEDRIVE + HOMEPATH
TEMP: str = os.environ['TEMP']
TMP: str = os.environ['TMP']
WBEM: str = f'{WINDOWS}\\{'System32' if sys.maxsize > 2 ** 32 else ('SysWOW64' if sys.maxsize < 2 ** 32 else 'System32')}\\wbem'     # WMI path
DRIVERS: str = f'{WINDOWS}\\{'System32' if sys.maxsize > 2 ** 32 else ('SysWOW64' if sys.maxsize < 2 ** 32 else 'System32')}\\drivers'


##############################################################################
def _get_folder(csidl: int) -> (str | None):
    path = (WCHAR * MAX_PATH)()
    shiobj.SHGetFolderPath(NULL, csidl | shiobj.CSIDL_FLAG_NO_ALIAS, NULL, shiobj.SHGFP_TYPE_CURRENT, path)
    return path.value if os.path.exists(path.value) else None


def Desktop(common: bool = False):
    return _get_folder(shiobj.CSIDL_COMMON_DESKTOPDIRECTORY if common else shiobj.CSIDL_DESKTOP)


def Roaming():
    return _get_folder(shiobj.CSIDL_APPDATA)


def INetCache():
    return _get_folder(shiobj.CSIDL_INTERNET_CACHE)


def INetCookies():
    return _get_folder(shiobj.CSIDL_COOKIES)


def Favorites():
    return _get_folder(shiobj.CSIDL_FAVORITES)


def History():
    return _get_folder(shiobj.CSIDL_HISTORY)


def Local():
    return _get_folder(shiobj.CSIDL_LOCAL_APPDATA)


def Music(common: bool = False):
    return _get_folder(shiobj.CSIDL_COMMON_MUSIC if common else shiobj.CSIDL_MYMUSIC)


def Pictures(common: bool = False):
    return _get_folder(shiobj.CSIDL_COMMON_PICTURES if common else shiobj.CSIDL_MYPICTURES)


def Videos(common: bool = False):
    return _get_folder(shiobj.CSIDL_COMMON_VIDEO if common else shiobj.CSIDL_MYVIDEO)


def Network_Shortcuts():
    return _get_folder(shiobj.CSIDL_NETHOOD)


def Documents(common: bool = False):
    return _get_folder(shiobj.CSIDL_COMMON_DOCUMENTS if common else shiobj.CSIDL_MYDOCUMENTS)


def Printer_Shortcuts():
    return _get_folder(shiobj.CSIDL_PRINTHOOD)


def Programs(common: bool = False):
    return _get_folder(shiobj.CSIDL_COMMON_PROGRAMS if common else shiobj.CSIDL_PROGRAMS)


def Recent():
    return _get_folder(shiobj.CSIDL_RECENT)


def SendTo():
    return _get_folder(shiobj.CSIDL_SENDTO)


def Start_Menu(common: bool = False):
    return _get_folder(shiobj.CSIDL_STARTMENU if common else shiobj.CSIDL_COMMON_STARTMENU)


def Startup(common: bool = False):
    return _get_folder(shiobj.CSIDL_COMMON_STARTUP if common else shiobj.CSIDL_ALTSTARTUP)


def Templates(common: bool = False):
    return _get_folder(shiobj.CSIDL_COMMON_TEMPLATES if common else shiobj.CSIDL_TEMPLATES)


def Downloads(): 
    path = c_wchar_p()
    shiobj.SHGetKnownFolderPath(knownfolders.FOLDERID_Downloads, NULL, NULL, byref(path))
    return path.value if os.path.exists(path.value) else None


def Administrative_Tools(common: bool = False):
    return _get_folder(shiobj.CSIDL_COMMON_ADMINTOOLS if common else shiobj.CSIDL_ADMINTOOLS)


def ProgramData():
    return _get_folder(shiobj.CSIDL_COMMON_APPDATA)


def Links():
    path = c_wchar_p()
    shiobj.SHGetKnownFolderPath(knownfolders.FOLDERID_Links, NULL, NULL, byref(path))
    return path.value if os.path.exists(path.value) else None


def Program_Files(X86: bool = False):
    return _get_folder(shiobj.CSIDL_PROGRAM_FILESX86 if X86 and WIN64 else shiobj.CSIDL_PROGRAM_FILES)


def Common_Files(X86: bool = False):
    return _get_folder(shiobj.CSIDL_PROGRAM_FILES_COMMONX86 if X86 and WIN64 else shiobj.CSIDL_PROGRAM_FILES_COMMON)
