# coding = 'utf-8'

import subprocess
from core.sys_win import *
from core.windows import *
from core.messagebox import *
from core.TaskDialogIndirect import *

# messagebox

print(MessageBox(HWND(), 'abc', 'abc', MB_ICONINFORMATION)) 
print(MessageBoxEx(HWND(), 'hello world', 'News', MB_ICONINFORMATION))
print("info", showinfo("Spam", "Egg Information"))
print("warning", showwarning("Spam", "Egg Warning"))
print("error", showerror("Spam", "Egg Alert"))
print("question", askquestion("Spam", "Question?"))
print("proceed", askokcancel("Spam", "Proceed?"))
print("yes/no", askyesno("Spam", "Got it?"))
print("yes/no/cancel", askyesnocancel("Spam", "Want it?"))
print("try again", askretrycancel("Spam", "Try again?"))
print(MessageBoxIndirect(lpCaption='News', lpszText='Hello World!', dwStyle=MB_OKCANCEL | MB_ICONINFORMATION))

# TaskDialogIndirect

print(TaskDialog(pszWindowTitle='News', 
                 pszMainInstruction='Hello World!', 
                 pszContent='Welcome to Python!', 
                 pszIcon=TD_INFORMATION_ICON, 
                 dwCommonButtons=TDCBF_OK_BUTTON)
)

print(TaskDialogIndirect(pszWindowTitle= 'News', 
                         pszMainInstruction='Hello World!', 
                         pszContent='Welcome to Python!', 
                         pszMainIcon=TD_INFORMATION_ICON, 
                         Buttons=[TASKDIALOG_BUTTON(100, '确定'), TASKDIALOG_BUTTON(101, '取消')],      
                         dwCommonButtons=TDCBF_RETRY_BUTTON,      
                         RadioButtons=[TASKDIALOG_BUTTON(2025, '选项1'), TASKDIALOG_BUTTON(2026, '选项2')], 
                         pszVerificationText='I agree.')
)

# sys_win -- wmi_query_proc
name, pid, path, *_ = wmi_query_proc()
num = 0
print(f'{'ProcessName':30} {'pid':^30} {'path'}')
print('='*100)
while True:
    try:
        print(f'{name[num]:30} {pid[num]:^30} {path[num] or 'None'}')
    except IndexError:
        break
    num += 1


# ===========================================================
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


Run()
cmd(True)
PowerShell(True)