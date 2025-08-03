# coding = 'utf-8'

from ctypes import WinDLL

User32 = WinDLL('User32.dll', use_last_error=True)
comctl32 = WinDLL('comctl32.dll', use_last_error=True)
Kernel32 = WinDLL('Kernel32.dll', use_last_error=True)
shell32 = WinDLL('shell32.dll', use_last_error=True)
ntdll = WinDLL('ntdll.dll', use_last_error=True)
advapi32 = WinDLL('advapi32.dll', use_last_error=True)