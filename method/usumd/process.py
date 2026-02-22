# coding = 'utf-8'

import os
from method.System.winusutypes import *
from method.System import otherapi, windows, tlhelp32


def get_proc_pid(proc_name: str) -> (int | None):
    '''通过已运行的程序获取对应的 pid'''
    hSnapshot = tlhelp32.CreateToolhelp32Snapshot(tlhelp32.TH32CS_SNAPPROCESS, 0)
    pe = tlhelp32.PROCESSENTRY32W()
    pe.dwSize = sizeof(pe)
    tlhelp32.Process32First(hSnapshot, byref(pe))

    try:
        while True:
            if pe.szExeFile.lower() != proc_name.lower():
                tlhelp32.Process32Next(hSnapshot, byref(pe))
                continue
            return pe.th32ProcessID
    except:
        return None
    

def ntpath_to_win32(nt_path: str) -> str:
    r'''
    将 NT 格式路径（如 \Device\HarddiskVolume1\Windows\...）转换为 Win32 路径（如 C:\Windows\...）
    如果转换失败，返回原路径。
    '''

    # 获取所有逻辑驱动器字符串
    drives_buffer = (WCHAR * MAX_PATH)()
    windows.GetLogicalDriveStrings(MAX_PATH, drives_buffer)

    # 建立 NT 设备名到 DOS 设备名的映射
    nt_to_dos: dict[str, str] = {}
    drives = ''.join(drives_buffer).split('\x00')
    for drive in drives:
        if not drive: break
        # 驱动器名如 "C:\"，去掉末尾反斜杠，得到 "C:"
        dos_name = drive.rstrip('\\')
        # 查询该 DOS 设备对应的 NT 设备名
        target_buffer = (WCHAR * MAX_PATH)()
        if windows.QueryDosDevice(dos_name, target_buffer, MAX_PATH, errcheck=False):
            nt_device = target_buffer.value
            nt_to_dos[nt_device] = dos_name

    # 尝试匹配 NT 路径的前缀
    for nt_device, dos_name in nt_to_dos.items():
        if nt_path.startswith(nt_device):
            win32_path = nt_path.replace(nt_device, dos_name, 1)
            return os.path.normpath(win32_path)
    return nt_path


def GetProcessOrServPathById(ProcessId: int) -> str:
    spii = otherapi.SYSTEM_PROCESS_ID_INFORMATION()
    spii.ProcessId = ProcessId
    spii.ImageName = (0, 0x80)
    while True:
        if spii.ImageName.Buffer:
            windows.LocalFree(spii.ImageName.Buffer)
        
        spii.ImageName.Buffer = cast(windows.LocalAlloc(windows.LMEM_FIXED, spii.ImageName.MaximumLength, False), PWSTR)
        if not spii.ImageName.Buffer:
            status = windows.STATUS_NO_MEMORY
            break

        status = otherapi.NtQuerySystemInformation(otherapi.SystemProcessIdInformation, byref(spii), sizeof(spii), NULL, False)
        if status != windows.STATUS_INFO_LENGTH_MISMATCH:
            break
    
    if status < 0:
        windows.ntstatus_to_errcheck(status)
        
    nt_path = string_at(spii.ImageName.Buffer, spii.ImageName.Length).decode('utf-16')
    win32_path = ntpath_to_win32(nt_path)
    
    if spii.ImageName.Buffer:
        windows.LocalFree(spii.ImageName.Buffer)
    return win32_path


def get_proc_path(proc_name: str) -> (str | None):
    '''通过已运行的程序来获取文件位置'''
    try:
        return GetProcessOrServPathById(get_proc_pid(proc_name))
    except:
        return None


def get_exec_title_from_hwnd(hwnd: int) -> (str | None):
    '''通过 hwnd 来获取已运行程序的标题'''
    try:
        textLenInCharacters = windows.GetWindowTextLength(hwnd)
        stringBuffer = (WCHAR * (textLenInCharacters + 1))()
        windows.GetWindowText(hwnd, stringBuffer, textLenInCharacters + 1)
    except:
        return None
    return stringBuffer.value


def get_exec_hwnd_from_title(title: str) -> list[int]:
    '''通过目标窗口标题来获取 hwnd'''
    hwnds = []
    for hwnd in get_all_exec_hwnd():
        try:
            if title == get_exec_title_from_hwnd(hwnd):
                hwnds.append(hwnd)
        except:
            pass
    return hwnds


def get_all_exec_hwnd(get_visible_window_hwnd: bool = False) -> list[int]:
    '''获取所有已运行程序的 hwnd'''
    window_hwnds = []
    def foreach_window(hWnd, lParam):
        if windows.IsWindowVisible(hWnd) or get_visible_window_hwnd:
            window_hwnds.append(hWnd)
        return True
    windows.EnumWindows(windows.EnumWindowsProc(foreach_window), 0)
    return window_hwnds


def get_all_exec_title() -> list[str | None]:
    '''获取所有已运行程序的标题'''
    titles = []
    for hwnd in get_all_exec_hwnd(True):
        titles.append(get_exec_title_from_hwnd(hwnd))
    return titles


def get_exec_hwnd_from_pid(pid: int) -> (int | None):
    '''通过目标程序的 PID 来获取 hwnd'''
    if not isinstance(pid, int):
        raise TypeError(f"The object should be of int, not {type(pid).__name__}")
    
    hwnds = get_all_exec_hwnd(True)
    for hwnd in hwnds:
        process_id = HANDLE()
        try:
            windows.GetWindowThreadProcessId(hwnd, byref(process_id))
        except:
            return None
        
        if process_id.value == pid:
            return hwnd  
    return None 


def get_exec_pid_from_hwnd(hwnd: int) -> (int | None):
    '''通过目标程序的 hwnd 来获取 PID'''

    if not isinstance(hwnd, int):
        raise TypeError(f"The object should be of int, not {type(hwnd).__name__}")
    
    try:
        pid = HANDLE()
        windows.GetWindowThreadProcessId(hwnd, byref(pid))
        return pid.value
    except:
        return None


def OpenTerminateProcess(pid: int) -> None:
    handle = windows.OpenProcess(windows.PROCESS_TERMINATE, False, pid, False)
    windows.TerminateProcess(handle, 0)
    windows.CloseHandle(handle)


