# coding = 'utf-8'

import sys
from method.System.windows import *
from method.System.shellapi import *
from method.System.tlhelp32 import *
from method.System.processthreadsapi import OpenProcess
from method.System.winnt import PROCESS_QUERY_LIMITED_INFORMATION


def get_proc_pid(proc_name: str) -> (int | None):
    '''通过已运行的程序获取对应的 pid'''
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PROCESSENTRY32W()
    pe.dwSize = sizeof(pe)
    Process32First(hSnapshot, byref(pe))

    try:
        while True:
            if pe.szExeFile.lower() != proc_name.lower():
                Process32Next(hSnapshot, byref(pe))
                continue
            return pe.th32ProcessID
    except:
        return None


def get_proc_path(proc_name: str) -> (str | None):
    '''通过已运行的程序来获取文件位置'''
    return get_serv_or_proc_path(get_proc_pid(proc_name))


def get_serv_or_proc_path(pid: int,
                          dwDesiredAccess: int = PROCESS_QUERY_LIMITED_INFORMATION, 
                          bInheritHandle: bool = False, 
                          dwFlags: int = NULL, 
                          lpExeName: int = MAX_PATH,
                          unicode: bool = True) -> (str | bytes | None):
    
    '''
    Get the location of the file by using the PID of the running program or service.
    （通过已运行的程序或服务的进程ID来获取文件位置）
    '''
    path = ((WCHAR if unicode else CHAR) * lpExeName)()
    lpdwSize = DWORD(sizeof(path))

    try:
        handle = OpenProcess(dwDesiredAccess=dwDesiredAccess, 
                            bInheritHandle=bInheritHandle, 
                            dwProcessId=pid
        )

        QueryFullProcessImageName(handle, dwFlags, byref(path), byref(lpdwSize), unicode)
        CloseHandle(handle)
        return path.value
    except:
        return None


def get_exec_hwnd_to_title(hwnd: int) -> (str | None):
    '''通过 hwnd 来获取已运行程序的标题'''
    try:
        textLenInCharacters = GetWindowTextLength(hwnd)
        stringBuffer = (WCHAR * (textLenInCharacters + 1))()
        GetWindowText(hwnd, stringBuffer, textLenInCharacters + 1)
    except:
        return None
    return stringBuffer.value


def get_goal_title_to_hwnd(title: str) -> list[int]:
    '''通过目标窗口标题来获取 hwnd'''
    hwnds = []
    for hwnd in get_all_exec_hwnd():
        try:
            if title == get_exec_hwnd_to_title(hwnd):
                hwnds.append(hwnd)
        except:
            pass
    return hwnds


def get_all_exec_hwnd(get_visible_window_hwnd: bool = False) -> list[int]:
    '''获取所有已运行程序的 hwnd'''
    window_hwnds = []
    def foreach_window(hWnd, lParam):
        if IsWindowVisible(hWnd) or get_visible_window_hwnd:
            window_hwnds.append(hWnd)
        return True
    EnumWindows(EnumWindowsProc(foreach_window), 0)
    return window_hwnds


def get_all_exec_title() -> list[str | None]:
    '''获取所有已运行程序的标题'''
    titles = []
    for hwnd in get_all_exec_hwnd(True):
        titles.append(get_exec_hwnd_to_title(hwnd))
    return titles


def get_goal_exec_pid_to_hwnd(pid: int) -> (int | None):
    '''通过目标程序的 PID 来获取 hwnd'''
    if not isinstance(pid, int):
        raise TypeError(f"The object should be of int, not {type(pid).__name__}")
    
    hwnds = get_all_exec_hwnd(True)
    for hwnd in hwnds:
        process_id = HANDLE()
        try:
            GetWindowThreadProcessId(hwnd, byref(process_id))
        except:
            return None
        
        if process_id.value == pid:
            return hwnd  
    return None 


def get_goal_exec_hwnd_to_pid(hwnd: int) -> (int | None):
    '''通过目标程序的 hwnd 来获取 PID'''

    if not isinstance(hwnd, int):
        raise TypeError(f"The object should be of int, not {type(hwnd).__name__}")
    
    try:
        pid = HANDLE()
        GetWindowThreadProcessId(hwnd, byref(pid))
        return pid.value
    except:
        return None


