# coding = 'utf-8'

from ctypes import WinDLL, CDLL

user32 = WinDLL('user32.dll', use_last_error=True)
comctl32 = WinDLL('comctl32.dll', use_last_error=True)
kernel32 = WinDLL('kernel32.dll', use_last_error=True)
shell32 = WinDLL('shell32.dll', use_last_error=True)
ntdll = WinDLL('ntdll.dll', use_last_error=True)
advapi32 = WinDLL('advapi32.dll', use_last_error=True)
winsta = WinDLL('winsta.dll', use_last_error=True)
ole32 = WinDLL('ole32.dll', use_last_error=True)
oleaut32 = WinDLL('oleaut32.dll', use_last_error=True)
comdlg32 = WinDLL('Comdlg32.dll', use_last_error=True)
wtsapi32 = WinDLL('wtsapi32.dll', use_last_error=True)
msvcrt = CDLL('msvcrt.dll', use_last_error=True, use_errno=True)

