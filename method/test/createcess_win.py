# coding = 'utf-8'

import subprocess
from method.device_method.windows import *
from method.device_method.sys_win import RunAsAdmin
from method.device_method.shellapi import ShellExecute


def cmd(admin = False, hwnd = None, nShow = SW_NORMAL) -> None:
    try:
        if admin: RunAsAdmin(nShow=nShow, hwnd=hwnd)
        subprocess.run(['cmd.exe'], shell=True, check=True)
    except OSError:
        pass


def PowerShell(admin = False, hwnd = None, nShow = SW_NORMAL) -> None:
    try:
        if admin: RunAsAdmin(nShow=nShow, hwnd=hwnd)
        subprocess.run(['powershell.exe'], shell=True, check=True)
    except OSError:
        pass


def Run():
    # Run CLSID: {2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}
    ShellExecute(lpFile='shell:::{2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}')
