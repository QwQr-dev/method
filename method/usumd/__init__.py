# coding = 'utf-8'


import os, sys
import subprocess
from method.System import shellapi
from method.System.winbase import *
from method.System.errcheck import *
from method.System.winusutypes import *
from method.System.winuser import IsUserAnAdmin
from method.System.processenv import GetCommandLine
from method.System.winreg import InitiateSystemShutdown
# from method.System.securitybaseapi import GetTokenInformation
from method.System.combaseapi import CoInitialize, CoUninitialize
from method.System.processthreadsapi import GetCurrentProcess, OpenProcessToken
# from method.System.winnt import TokenUIAccess, TOKEN_QUERY, PROCESS_QUERY_INFORMATION
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
        GetCurrentDirectory(MAX_PATH, byref(path))
        return path.value
    return path


def open_file_location(path: str | None = None) -> None:
    """通过文件路径在文件资源管理器中打开文件所在位置并选中文件"""
    
    path = os.path.abspath(null_to_nullstr(path))
    if not os.path.exists(path):
        raise FileNotFoundError(f'No such file or directory: {path}')
    
    shellapi.ShellExecute(
        lpFile='explorer.exe', 
        lpParameters=f'/select, {path}',
        hwnd=None,
        lpDirectory=None,
        lpOperation=None,
        nShowCmd=shellapi.SW_NORMAL
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


# def IsUIAccess() -> bool:
#     '''检查已运行的程序是否具有 UIAccess 权限'''
#     Token = HANDLE()
#     Handle = shellapi.OpenProcess(
#         PROCESS_QUERY_INFORMATION, 
#         FALSE, 
#         shellapi.GetCurrentProcessId()
#     )
# 
#     shellapi.OpenProcessToken(Handle, TOKEN_QUERY, byref(Token))
#     UIAccess = DWORD()
#     Return_Length = DWORD()
#     GetTokenInformation(
#         Token, 
#         TokenUIAccess, 
#         byref(UIAccess), 
#         sizeof(UIAccess), 
#         byref(Return_Length)
#     )
# 
#     shellapi.CloseHandle(Token)
#     return bool(UIAccess.value)


def RunAsAdmin(
    hwnd: int | None = None, 
    fMask: int = shellapi.SEE_MASK_NOCLOSEPROCESS | shellapi.SEE_MASK_NO_CONSOLE, 
    lpVerb: str = 'runas', 
    lpFile: str = sys.executable, 
    lpDirectory: str = '',
    lpParameters: str = os.path.normpath(subprocess.list2cmdline(sys.argv)), 
    nShow: int = shellapi.SW_NORMAL
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

    if IsUserAnAdmin():
        return
    
    mbr = shellapi.SHELLEXECUTEINFOW()
    mbr.cbSize = sizeof(mbr)
    mbr.fMask = fMask
    mbr.hwnd = hwnd
    mbr.lpVerb = lpVerb
    mbr.lpFile = lpFile
    mbr.lpParameters = lpParameters
    mbr.lpDirectory = lpDirectory
    mbr.nShow = nShow
    try:
        shellapi.ShellExecuteEx(byref(mbr))
    except:
        pass
    sys.exit(0)


def RunAsAdmin2(
    hwnd: int | None = None,
    lpOperation: str= 'runas', 
    lpFile: str = sys.executable, 
    lpParameters: str= f'{os.path.abspath(sys.argv[0])} --admin',
    lpDirectory: str= '',
    nShowCmd: int = shellapi.SW_NORMAL
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
    
    if IsUserAnAdmin():
        return
    
    if '--admin'not in GetCommandLine():
        try:
            shellapi.ShellExecute(
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
    LookupPrivilegeValue(NULL, privilegeName, byref(luid))

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    res = AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), NULL, 0, False)
    if not res:
        raise WinError(GetLastError())
    

def _EnablePrivilege(privilegeName: str):
    hToken = HANDLE()
    res = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, byref(hToken), False)
    if not res:
        raise WinError(GetLastError())
    
    _EnablePrivilegeWithToken(hToken, privilegeName)
    shellapi.CloseHandle(hToken)


def shutdown(
    MachineName: str | None = None, 
    Message: str | None = None, 
    Timeout: int = 60, 
    ForceAppsClosed: bool = False,
    Reboot: bool = False
) -> NoReturn:
    
    # 见微软文档
    # https://learn.microsoft.com/zh-cn/windows/win32/api/winreg/nf-winreg-initiatesystemshutdownw

    '''
    shutdown 的 Docstring
    
    :param MachineName: 要关闭的计算机的网络名称。
    :type MachineName: str | None

    :param Message: 要显示在关闭对话框中的消息。
    :type Message: str | None

    :param Timeout: 应显示关闭对话框的时间长度（以秒为单位）。
    :type Timeout: int

    :param ForceAppsClosed: 如果此参数 TRUE，则具有未保存更改的应用程序将被强行关闭。 
    请注意，这可能会导致数据丢失。如果此参数 FALSE，系统将显示一个对话框，指示用户关闭应用程序。
    :type ForceAppsClosed: bool

    :param Reboot: 如果此参数 TRUE，则计算机在关闭后立即重启，如果此参数 FALSE，系统会将所有缓存刷新到磁盘并安全地关闭系统。
    :type Reboot: bool
    '''
    
    _EnablePrivilege(SE_SHUTDOWN_NAME)
    InitiateSystemShutdown(MachineName, Message, Timeout, ForceAppsClosed, Reboot)
