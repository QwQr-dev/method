# coding = 'utf-8'

import os, sys
import subprocess
from method.usumd.syspath import *
from method.System.errcheck import *
from method.System.winusutypes import *
from method.System import windows as _ws
from method.System.combaseapi import CoInitialize, CoUninitialize
from method.System.shiobj import ILCreateFromPath, ILFree, SHOpenFolderAndSelectItems
from method.System.winnt import LUID, SE_PRIVILEGE_ENABLED, SE_SHUTDOWN_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY
from . import (
    messagebox,
    filedialog,
    syspath,
    systeminfo,
    process
)


def get_self_dir(temp_dir: bool = False) -> str:
    '''获取文件自身路径'''

    if temp_dir:
        return os.path.abspath(__file__)
    
    path = os.path.dirname(os.path.abspath(sys.argv[0]))
    if not os.path.exists(path):
        path = (WCHAR * MAX_PATH)()
        _ws.GetCurrentDirectory(MAX_PATH, byref(path))
        return path.value
    return path


def open_file_location(path: str | None = None) -> None:
    """通过文件路径在文件资源管理器中打开文件所在位置并选中文件"""
    
    path = os.path.abspath(null_to_nullstr(path))
    if not os.path.exists(path):
        raise FileNotFoundError(f'No such file or directory: {path}')
    
    _ws.ShellExecute(
        lpFile='explorer.exe', 
        lpParameters=f'/select, {path}',
        hwnd=None,
        lpDirectory=None,
        lpOperation=None,
        nShowCmd=_ws.SW_NORMAL
    )


def open_file_location2(path: str | None = None, dwFlags: int = 0) -> None:
    """通过文件路径在文件资源管理器中打开文件所在位置并选中文件"""

    path = os.path.abspath(null_to_nullstr(path))
    if not os.path.exists(path):
        raise FileNotFoundError(f'No such file or directory: {path}')
    
    pidl = ILCreateFromPath(path)
    CoInitialize()
    SHOpenFolderAndSelectItems(pidl, 0, NULL, dwFlags=dwFlags)
    CoUninitialize()
    ILFree(pidl)


def RunAsAdmin(
    hwnd: int | None = None, 
    fMask: int = _ws.SEE_MASK_NOCLOSEPROCESS | _ws.SEE_MASK_NO_CONSOLE, 
    lpVerb: str = 'runas', 
    lpFile: str = sys.executable, 
    lpDirectory: str = '',
    lpParameters: str = os.path.normpath(subprocess.list2cmdline(sys.argv)), 
    nShow: int = _ws.SW_NORMAL
) -> None:
    
    '''
    以管理员权限运行

    e.g. :
    =====

    >>> import subprocess
    >>> from method import RunAsAdmin
    >>> RunAsAdmin()
    >>> subprocess.run(['cmd.exe'], shell=True, check=True)
    '''

    if _ws.IsUserAnAdmin():
        return
    
    mbr = _ws.SHELLEXECUTEINFOW()
    mbr.cbSize = sizeof(mbr)
    mbr.fMask = fMask
    mbr.hwnd = hwnd
    mbr.lpVerb = lpVerb
    mbr.lpFile = lpFile
    mbr.lpParameters = lpParameters
    mbr.lpDirectory = lpDirectory
    mbr.nShow = nShow
    try:
        _ws.ShellExecuteEx(byref(mbr))
    except:
        pass
    sys.exit(0)


def RunAsAdmin2(
    hwnd: int | None = None,
    lpOperation: str= 'runas', 
    lpFile: str = sys.executable, 
    lpParameters: str= f'{os.path.abspath(sys.argv[0])} --admin',
    lpDirectory: str= '',
    nShowCmd: int = _ws.SW_NORMAL
) -> None:
    
    '''
    以管理员权限运行

    e.g. :
    =====

    >>> import subprocess
    >>> from method import RunAsAdmin2
    >>> RunAsAdmin2()
    >>> subprocess.run(['cmd.exe'], shell=True, check=True)
    '''
    
    if _ws.IsUserAnAdmin():
        return
    
    if '--admin'not in _ws.GetCommandLine():
        try:
            _ws.ShellExecute(
                lpOperation=lpOperation,
                lpFile=lpFile,
                lpParameters=lpParameters,
                hwnd=hwnd,
                nShowCmd=nShowCmd,
                lpDirectory=lpDirectory
            )
        except:
            pass

    sys.exit(0)


def _EnablePrivilegeWithToken(hToken: int, privilegeName: str):
    luid = LUID()
    _ws.LookupPrivilegeValue(NULL, privilegeName, byref(luid))

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    res = _ws.AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), NULL, 0, False)
    if not res:
        raise WinError(GetLastError())
    

def _EnablePrivilege(privilegeName: str):
    hToken = HANDLE()
    res = _ws.OpenProcessToken(_ws.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, byref(hToken), False)
    if not res:
        raise WinError(GetLastError())
    
    _EnablePrivilegeWithToken(hToken, privilegeName)
    _ws.CloseHandle(hToken)


def shutdown(
    MachineName: str | None = None, 
    Message: str | None = None, 
    Timeout: int = 60, 
    ForceAppsClosed: bool = False,
    Reboot: bool = False
) -> NoReturn:
    
    _EnablePrivilege(SE_SHUTDOWN_NAME)
    _ws.InitiateSystemShutdown(MachineName, Message, Timeout, ForceAppsClosed, Reboot)
