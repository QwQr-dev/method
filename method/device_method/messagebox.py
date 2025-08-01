# coding = 'utf-8'

'''
The messagebox was used Windows API to make. 
Some ways had the messagebox of tkinter in common.
'''

import ctypes
from typing import Any

try:
    from windows import *
except ImportError:
    from .windows import *


def MessageBox(hwnd: int = HWND(), 
               lpText: str = '', 
               lpCaption: str = '', 
               uType: int = UINT(), 
               unicode: bool = True) -> int:
    
    if unicode:
        result = User32.MessageBoxW(hwnd, 
                                lpText, 
                                lpCaption, 
                                uType
        )
    else:
        result = User32.MessageBoxA(hwnd, 
                                lpText, 
                                lpCaption, 
                                uType
        )
    
    if result == NULL:
        raise ctypes.WinError(Kernel32.GetLastError(result))
    return result


def MessageBoxEx(hwnd: int = HWND(), 
                 lpText: str = '', 
                 lpCaption: str = '', 
                 uType: int = INT(), 
                 wLanguageId: int = INT(), 
                 unicode: bool = True) -> int:
    
    if unicode:
        result = User32.MessageBoxExW(hwnd, 
                                  lpText, 
                                  lpCaption, 
                                  uType, 
                                 wLanguageId
        )
    else:
        result = User32.MessageBoxExA(hwnd, 
                                  lpText, 
                                  lpCaption, 
                                  uType, 
                                 wLanguageId
        )

    if result == NULL:
        raise ctypes.WinError(Kernel32.GetLastError(result))
    return result
    

def MessageBeep(uType: int) -> bool:
    return bool(User32.MessageBeep(uType))


def showinfo(lpCaption: str = '', 
             lpText: str = '', 
             hwnd: int = HWND(), 
             unicode: bool = True) -> bool:
    
    return bool(MessageBox(hwnd=hwnd, 
                           lpCaption=lpCaption, 
                           lpText=lpText, 
                           uType=MB_ICONINFORMATION, 
                           unicode=unicode)
    )


def showwarning(lpCaption: str = '', 
                lpText: str = '', 
                hwnd: int = HWND(), 
                unicode: bool = True) -> bool:
    
    return bool(MessageBox(hwnd=hwnd, 
                           lpCaption=lpCaption, 
                           lpText=lpText, 
                           uType=MB_ICONWARNING, 
                           unicode=unicode)
    )


def showerror(lpCaption: str = '', 
              lpText: str = '', 
              hwnd: int = HWND(), 
              unicode: bool = True) -> bool:
    
    return bool(MessageBox(hwnd=hwnd, 
                           lpCaption=lpCaption, 
                           lpText=lpText, 
                           uType=MB_ICONERROR, 
                           unicode=unicode)
    )


def askquestion(lpCaption: str = '', 
                lpText: str = '', 
                hwnd: int = HWND(), 
                unicode: bool = True) -> bool:
    
    MessageBeep(MB_ICONINFORMATION)
    return bool(MessageBox(hwnd=hwnd, 
                           lpCaption=lpCaption, 
                           lpText=lpText, 
                           uType=MB_ICONQUESTION, 
                           unicode=unicode)
    )


def askokcancel(lpCaption: str = '', 
                lpText: str = '', 
                hwnd: int = HWND(), 
                unicode: bool = True) -> bool:
    
    MessageBeep(MB_ICONINFORMATION)
    result = MessageBox(hwnd=hwnd, 
                        lpCaption=lpCaption, 
                        lpText=lpText, 
                        uType=MB_ICONQUESTION | MB_OKCANCEL, 
                        unicode=unicode
    )

    return True if result == IDOK else False


def askyesno(lpCaption: str = '', 
             lpText: str = '', 
             hwnd: int = HWND(), 
             unicode: bool = True) -> bool:
    
    MessageBeep(MB_ICONINFORMATION)
    result = MessageBox(hwnd=hwnd, 
                        lpCaption=lpCaption, 
                        lpText=lpText, 
                        uType=MB_ICONQUESTION | MB_OKCANCEL, 
                        unicode=unicode
    )

    return True if result == IDOK else False


def askyesnocancel(lpCaption: str = '', 
                   lpText: str = '', 
                   hwnd: int = HWND(), 
                   unicode: bool = True) -> (bool | None):
    
    MessageBeep(MB_ICONINFORMATION)
    result = MessageBox(hwnd=hwnd, 
                        lpCaption=lpCaption, 
                        lpText=lpText, 
                        uType=MB_ICONQUESTION | MB_YESNOCANCEL, 
                        unicode=unicode
    )
    
    if result == IDYES:
        return True
    elif result == IDNO:
        return False
    return None


def askretrycancel(lpCaption: str = '', 
                   lpText: str = '', 
                   hwnd: int = HWND(), 
                   unicode: bool = True) -> bool:
    
    result = MessageBox(hwnd=hwnd, 
                        lpCaption=lpCaption, 
                        lpText=lpText, 
                        uType=MB_ICONWARNING | MB_RETRYCANCEL, 
                        unicode=unicode
    )
    
    return True if result == IDRETRY else False


def MessageBoxIndirect(hwndOwner: int = HWND(), 
                       hInstance: int = HINSTANCE(), 
                       lpszText: str = '', 
                       lpCaption: str = '', 
                       dwStyle: Any = DWORD(), 
                       lpszIcon: str = '', 
                       dwContextHelpId: Any = DWORD_PTR(), 
                       lpfnMsgBoxCallback: Any = MSGBOXCALLBACK(), 
                       dwLanguageId: Any = DWORD(), 
                       unicode: bool = True) -> int:
    
    MessageBoxIndirectW = User32.MessageBoxIndirectW
    MessageBoxIndirectA = User32.MessageBoxIndirectA

    mbp = MSGBOXPARAMSW() if unicode else MSGBOXPARAMSA()
    mbp.cbSize = ctypes.sizeof(mbp)
    mbp.hwndOwner = hwndOwner
    mbp.hInstance = hInstance
    mbp.lpszText = lpszText
    mbp.lpszCaption = lpCaption
    mbp.dwStyle = dwStyle
    mbp.lpszIcon = lpszIcon
    mbp.dwContextHelpId = dwContextHelpId
    mbp.lpfnMsgBoxCallback = lpfnMsgBoxCallback
    mbp.dwLanguageId = dwLanguageId

    result = MessageBoxIndirectW(ctypes.byref(mbp)) if unicode else MessageBoxIndirectA(ctypes.byref(mbp))

    if result == NULL:
        raise ctypes.WinError(Kernel32.GetLastError(result))
    return result


if __name__ == '__main__':
    # test

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

