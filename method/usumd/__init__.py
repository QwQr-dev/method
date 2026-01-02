# coding = 'utf-8'

import os, sys
import subprocess
from method.System.shellapi import *
from method.System.otherapi import *
from method.System.winusutypes import *
from method.System.winuser import IsUserAnAdmin
from method.System.combaseapi import CoInitialize, CoUninitialize
from method.System.winnt import TokenUIAccess, TOKEN_QUERY, PROCESS_QUERY_INFORMATION
from method.System.shiobj import ILCreateFromPath, ILFree, SHOpenFolderAndSelectItems
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


def open_file_location(path: str) -> None:
    """通过文件路径在文件资源管理器中打开文件所在位置并选中文件"""
    
    path = os.path.normpath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f'No such file or directory: {path}')
    
    ShellExecute(
        lpFile='explorer.exe', 
        lpParameters=f'/select, {path}',
        hwnd=None,
        lpDirectory=None,
        lpOperation=None,
        nShowCmd=SW_NORMAL
    )


def open_file_location2(path: str, dwFlags: int = NULL) -> None:
    """通过文件路径在文件资源管理器中打开文件所在位置并选中文件"""
    
    if path.startswith('.') or path.startswith('..'):
        path = os.path.abspath(path)

    path = os.path.normpath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f'No such file or directory: {path}')
    
    pidl = ILCreateFromPath(path)
    CoInitialize()
    SHOpenFolderAndSelectItems(pidl, NULL, NULL, dwFlags=dwFlags)
    CoUninitialize()
    ILFree(pidl)


def IsUIAccess() -> bool:
    '''检查已运行的程序是否具有 UIAccess 权限'''
    Token = HANDLE()
    Handle = OpenProcess(
        PROCESS_QUERY_INFORMATION, 
        FALSE, 
        GetCurrentProcessId()
    )

    OpenProcessToken(Handle, TOKEN_QUERY, byref(Token))
    UIAccess = DWORD()
    Return_Length = DWORD()
    GetTokenInformation(
        Token, 
        TokenUIAccess, 
        byref(UIAccess), 
        sizeof(UIAccess), 
        byref(Return_Length)
    )

    CloseHandle(Token)
    return bool(UIAccess.value)


def RunAsAdmin(
    hwnd: int = NULL, 
    fMask: int = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE, 
    lpVerb: str | bytes = 'runas', 
    lpFile: str | bytes = sys.executable, 
    lpDirectory: str | bytes = '',
    lpParameters: str | bytes = os.path.normpath(subprocess.list2cmdline(sys.argv)), 
    nShow: int = SW_NORMAL,
    unicode: bool = True
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
    
    mbr = (SHELLEXECUTEINFOW if unicode else SHELLEXECUTEINFOA)()
    mbr.cbSize = sizeof(mbr)
    mbr.fMask = fMask
    mbr.hwnd = hwnd
    mbr.lpVerb = lpVerb
    mbr.lpFile = lpFile
    mbr.lpParameters = lpParameters
    mbr.lpDirectory = lpDirectory
    mbr.nShow = nShow
    try:
        ShellExecuteEx(byref(mbr), unicode)
    except:
        pass
    sys.exit(0)


def RunAsAdmin2(
    hwnd: int = NULL,
    lpOperation: str | bytes = 'runas', 
    lpFile: str | bytes = sys.executable, 
    lpParameters: str | bytes = f'{os.path.abspath(sys.argv[0])} --admin',
    lpDirectory: str | bytes = '',
    nShowCmd: int = SW_NORMAL,
    unicode: bool = True
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
    
    if ('--admin' if unicode else b'--admin') not in GetCommandLine(unicode):
        try:
            ShellExecute(
                lpOperation=lpOperation,
                lpFile=lpFile,
                lpParameters=lpParameters,
                hwnd=hwnd,
                nShowCmd=nShowCmd,
                unicode=unicode,
                lpDirectory=lpDirectory
            )
        except:
            pass

    sys.exit(0)


