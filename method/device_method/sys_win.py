# coding = 'utf-8'

''' The sys_win was used Windows API to make. '''

import os
import sys
import winreg
import platform
import subprocess
from typing import Any
from .windows import *
from win32com.client import GetObject
from .shellapi import (ShellExecute, 
                       ShellExecuteEx, 
                       OpenProcess, 
                       CloseHandle, 
                       QueryFullProcessImageName
)

wmi = GetObject('winmgmts:')

IsUserAnAdmin = shell32.IsUserAnAdmin
ShowWindow = User32.ShowWindow
WaitForSingleObject = Kernel32.WaitForSingleObject


def get_self_directory(temp_dir: bool = False) -> str:
    '''Get the path to your own file.（获取自身文件路径）'''

    return os.path.dirname(os.path.abspath(
        __file__ if temp_dir else sys.argv[0]))


def system_type(sys_type: bool = False) -> dict:
    from struct import calcsize

    reg_key = r"Software\Microsoft\Windows NT\CurrentVersion"
    DisplayVersion = 'DisplayVersion'
    EditionID = 'EditionID'
    CurrentBuild = 'CurrentBuild'
    UBR = 'UBR'

    for key in [EditionID, DisplayVersion, CurrentBuild, UBR]:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_key) as result:
            value, *_ = winreg.QueryValueEx(result, key)
   
        if key == DisplayVersion:
            DisplayVersion = value
        elif key == EditionID:
            EditionID = value
        elif key == CurrentBuild:
            CurrentBuild = value
        elif key == UBR:
            UBR = value
    
    result = {}
    major = sys.getwindowsversion().major
    minor = sys.getwindowsversion().minor
    NT_ver = f'{major}.{minor}'
    OS_type = platform.system()
    OS_ver = platform.release()
    OS_build = platform.version()
    OS_bits = str(calcsize('P') * 8)
    OS_machine = platform.machine().lower()
    OS_sp_ver = platform._win32_ver(version='', csd='', ptype='')[1]

    result['OS_type'] = OS_type
    result['OS_ver'] = OS_ver
    result['EditionID'] = EditionID
    result['DisplayVersion'] = DisplayVersion
    result['OS_machine'] = OS_machine
    result['OS_bits'] = OS_bits

    if sys_type: return result

    result['OS_build'] = OS_build
    result['OS_sp_ver'] = OS_sp_ver
    result['NT_ver'] = NT_ver
    result['NT_major'] = str(major)
    result['NT_minor'] = str(minor)
    result['CurrentBuild'] = CurrentBuild
    result['UBR'] = str(UBR)
    return result


def wmi_query_serv() -> tuple[list, list, list, list, list]:
    '''Call wmi to query the service.（调用wmi来查询服务）'''

    exitcode = []
    name = []
    pid = []
    startmode = []
    state = []
    Win32_Service = wmi.ExecQuery("SELECT * FROM Win32_Service")
    for service in Win32_Service:
        exitcode.append(service.ExitCode)
        name.append(service.Name)    
        pid.append(service.ProcessId) 
        startmode.append(service.StartMode)
        state.append(service.State)
    return exitcode, name, pid, startmode, state


def wmi_query_proc() -> tuple[list, list, list, list, list, list, list]:
    '''Call wmi to query the process.（调用wmi来查询进程）'''

    name = []
    pid = []
    path = []
    description = []
    parent_pid = []
    threadcount = []
    handles = []
    Win32_Process = wmi.ExecQuery("SELECT * FROM Win32_Process")
    
    for proc in Win32_Process:
        name.append(proc.Name)
        pid.append(proc.ProcessID)
        path.append(proc.ExecutablePath)
        description.append(proc.Description)
        parent_pid.append(proc.ParentProcessId)
        threadcount.append(proc.ThreadCount)
        handles.append(proc.HandleCount)
    
    num = 0
    for p in path:
        if '\\\\?\\' in str(p):
            path[num] = p[4:]
        num += 1
    return name, pid, path, description, parent_pid, threadcount, handles


def get_proc_path(proc_name: str) -> (str | None):
    '''Get the file location from a running program.
    （通过已运行的程序来获取文件位置）
    '''

    name, pid, path, *_ = wmi_query_proc()
    num = 0
    for proc in name:
        if proc_name.lower() == str(proc).lower():
            return path[num]
        num += 1
    return None


def get_serv_or_proc_path(pid: int,
                          dwDesiredAccess: int = PROCESS_QUERY_LIMITED_INFORMATION, 
                          bInheritHandle: bool = False, 
                          dwFlags: int = 0, 
                          lpExeName: Any = 260,
                          unicode: bool = True) -> (str | None):
    
    try:
        handle = OpenProcess(dwDesiredAccess=dwDesiredAccess, 
                            bInheritHandle=bInheritHandle, 
                            dwProcessId=pid
        )

        path = QueryFullProcessImageName(handle, 
                                        dwFlags=dwFlags,
                                        lpExeName=lpExeName,
                                        unicode=unicode
        )

        CloseHandle(handle)
        return path
    except Exception:
        return None


def open_file_location(path: str) -> None:
    """Open the location in Explorer through the file path and select the file.
    （通过文件路径在资源管理器中打开文件所在位置并选中文件）
    """
    
    path = os.path.normpath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f'No such file or directory: "{path}"')
    
    ShellExecute(lpOperation='open', 
                 lpFile='explorer.exe', 
                 lpParameters=f'/select, {path}'
    )


def press_kd_event(key: int, 
                   key1: int = 0, 
                   key2: int = 0, 
                   key3: int = 0) -> None:
    
    User32.keybd_event(key, key1, key2, key3)


def release_kd_event(key: int, 
                     key1: int = 0, 
                     key2: int=KEYEVENTF_KEYUP, 
                     key3: int = 0) -> None:
    
    User32.keybd_event(key, key1, key2, key3)


def RunAsAdmin(hwnd: int = HWND(), 
               fMask: int = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE, 
               lpVerb: str = 'runas', 
               lpFile: str = sys.executable, 
               lpParameters: str = subprocess.list2cmdline(sys.argv), 
               nShow: int = SW_NORMAL) -> None:
    
    if IsUserAnAdmin():
        return
    
    try:
        handle = ShellExecuteEx(hwnd=hwnd, 
                                fMask=fMask, 
                                lpVerb=lpVerb, 
                                lpFile=lpFile, 
                                lpParameters=lpParameters, 
                                nShow=nShow
        )
        WaitForSingleObject(handle, -1)
    except FileNotFoundError:
        pass
    
    CloseHandle(handle)
    sys.exit(0)


def enum_reg_value(root: int, path: str) -> dict:
    res = {}
    with winreg.OpenKey(root, path) as key:
        for j in range(winreg.QueryInfoKey(key)[1]):
            value_name, value_data, *_ = winreg.EnumValue(key, j)
            res[value_name] = value_data
        return res


_Volatile_Environment = 'Volatile Environment'
_User_Shell_Folders = r".DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
_Shell_Folders = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'

_Volatile_Environment_res: dict = enum_reg_value(winreg.HKEY_CURRENT_USER, _Volatile_Environment)
_User_Shell_Folders_res: dict = enum_reg_value(winreg.HKEY_USERS, _User_Shell_Folders)
_System_Shell_Folders_res: dict = enum_reg_value(winreg.HKEY_LOCAL_MACHINE, _Shell_Folders)

SYSTEMROOT: str = enum_reg_value(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\DriverDatabase')['SystemRoot']
APPDATA: str = _Volatile_Environment_res['APPDATA']
HOMEDRIVE: str = _Volatile_Environment_res['HOMEDRIVE']
HOMEPATH: str = _Volatile_Environment_res['HOMEPATH']
LOCALAPPDATA: str = _Volatile_Environment_res['LOCALAPPDATA']
LOGONSERVER: str = _Volatile_Environment_res['LOGONSERVER']
USERDOMAIN: str = _Volatile_Environment_res['USERDOMAIN']
USERDOMAIN_ROAMINGPROFILE: str = _Volatile_Environment_res['USERDOMAIN_ROAMINGPROFILE']
USERNAME: str = _Volatile_Environment_res['USERNAME']
USERPROFILE: str = _Volatile_Environment_res['USERPROFILE']
HOME: str = HOMEDRIVE + HOMEPATH
TEMP: str = os.environ['TEMP']
TMP: str = TEMP


def _get_user_folders() -> dict:
    New_User_Shell_Folders_res = {}
    for key in _User_Shell_Folders_res:
        value = _User_Shell_Folders_res[key].split('\\')

        if value[0] == '%USERPROFILE%':
            value[0] = USERPROFILE

        value = "\\".join(value)

        if key == '{374DE290-123F-4565-9164-39C4925E467B}':
            New_User_Shell_Folders_res['Downloads'] = value
            continue
        elif key == 'AppData':
            New_User_Shell_Folders_res['Roaming'] = value
            continue
        elif key == 'Cache':
            New_User_Shell_Folders_res['INetCache'] = value
            continue
        elif key == 'Cookies':
            New_User_Shell_Folders_res['INetCookies'] = value
            continue
        elif key == 'Local AppData':
            New_User_Shell_Folders_res['Local'] = value
            continue
        elif key == 'My Music':
            New_User_Shell_Folders_res['Music'] = value
            continue
        elif key == 'My Pictures':
            New_User_Shell_Folders_res['Pictures'] = value
            continue
        elif key == 'My Video':
            New_User_Shell_Folders_res['Videos'] = value
            continue
        elif key == 'NetHood':
            New_User_Shell_Folders_res['Network Shortcuts'] = value
            continue
        elif key == 'Personal':
            New_User_Shell_Folders_res['Documents'] = value
            continue
        elif key == 'PrintHood':
            New_User_Shell_Folders_res['Printer Shortcuts'] = value
            continue

        New_User_Shell_Folders_res[key] = value
    return New_User_Shell_Folders_res


def _get_system_folders() -> dict:
    New_System_Shell_Folders_res = {}
    for key in _System_Shell_Folders_res:
        value = _System_Shell_Folders_res[key]
        if key == 'Common Administrative Tools':
            New_System_Shell_Folders_res['Administrative Tools'] = value
            continue
        elif key == 'Common AppData':
            New_System_Shell_Folders_res['ProgramData'] = value
            continue
        elif key == 'Common Desktop':
            New_System_Shell_Folders_res['Desktop'] = value
            continue
        elif key == 'Common Documents':
            New_System_Shell_Folders_res['Documents'] = value
            continue
        elif key == 'Common Programs':
            New_System_Shell_Folders_res['Programs'] = value
            continue
        elif key == 'Common Start Menu':
            New_System_Shell_Folders_res['Start Menu'] = value
            continue
        elif key == 'Common Startup':
            New_System_Shell_Folders_res['Startup'] = value
            continue
        elif key == 'Common Templates':
            New_System_Shell_Folders_res['Templates'] = value
            continue
        elif key == 'CommonMusic':
            New_System_Shell_Folders_res['Music'] = value
            continue
        elif key == 'CommonPictures':
            New_System_Shell_Folders_res['Pictures'] = value
            continue
        elif key == 'CommonVideo':
            New_System_Shell_Folders_res['Videos'] = value
            continue
        elif key == 'OEM Links':
            New_System_Shell_Folders_res['Links'] = value
            continue
    return New_System_Shell_Folders_res


User_Shell_Folders: dict = _get_user_folders()
System_Shell_Folders: dict = _get_system_folders()


def Desktop(common: bool = False) -> str:
    if common:
        return _get_system_folders()['Desktop']
    return _get_user_folders()['Desktop']


def Roaming() -> str:
    return _get_user_folders()['Roaming']


def INetCache() -> str:
    return _get_user_folders()['INetCache']


def INetCookies() -> str:
    return _get_user_folders()['INetCookies']


def Favorites() -> str:
    return _get_user_folders()['Favorites']


def History() -> str:
    return _get_user_folders()['History']


def Local() -> str:
    return _get_user_folders()['Local']


def Music(common: bool = False) -> str:
    if common:
        return _get_system_folders()['Music']
    return _get_user_folders()['Music']


def Pictures(common: bool = False) -> str:
    if common:
        return _get_system_folders()['Pictures']
    return _get_user_folders()['Pictures']


def Videos(common: bool = False) -> str:
    if common:
        return _get_system_folders()['Videos']
    return _get_user_folders()['Videos']


def Network_Shortcuts() -> str:
    return _get_user_folders()['Network Shortcuts']


def Documents(common: bool = False) -> str:
    if common:
        return _get_system_folders()['Documents']
    return _get_user_folders()['Documents']


def Printer_Shortcuts() -> str:
    return _get_user_folders()['Printer Shortcuts']


def Programs(common: bool = False) -> str:
    if common:
        return _get_system_folders()['Programs']
    return _get_user_folders()['Programs']


def Recent() -> str:
    return _get_user_folders()['Recent']


def SendTo() -> str:
    return _get_user_folders()['SendTo']


def Start_Menu(common: bool = False) -> str:
    if common:
        return _get_system_folders()['Start Menu']
    return _get_user_folders()['Start Menu']


def Startup(common: bool = False) -> str:
    if common:
        return _get_system_folders()['Startup']
    return _get_user_folders()['Startup']


def Templates(common: bool = False) -> str:
    if common:
        return _get_system_folders()['Templates']
    return _get_user_folders()['Templates']


def Downloads() -> str:
    return _get_user_folders()['Downloads']


def Administrative_Tools() -> str:
    return _get_system_folders()['Administrative Tools']


def ProgramData() -> str:
    return _get_system_folders()['ProgramData']


def Links() -> str:
    return _get_system_folders()['Links']