# coding = 'utf-8'

'''
The messagebox was used Windows API to make. 
Some ways had the messagebox of tkinter in common.
'''

import winsound
from method.System import winuser
from method.System.winusutypes import *


def showinfo(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = 0, 
    unicode: bool = True
) -> bool:
    
    return bool(winuser.MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=winuser.MB_ICONINFORMATION | uType, 
        unicode=unicode)
    )


def showwarning(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = 0, 
    unicode: bool = True
) -> bool:
    
    return bool(winuser.MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=winuser.MB_ICONWARNING | uType, 
        unicode=unicode)
    )


def showerror(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = 0, 
    unicode: bool = True
) -> bool:
    
    return bool(winuser.MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=winuser.MB_ICONERROR | uType, 
        unicode=unicode)
    )


def askquestion(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = 0, 
    beep: int = winuser.MB_ICONINFORMATION,
    unicode: bool = True
) -> bool:
    
    winsound.MessageBeep(beep)
    return bool(winuser.MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=winuser.MB_ICONQUESTION | uType, 
        unicode=unicode)
    )


def askokcancel(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = 0, 
    beep: int = winuser.MB_ICONINFORMATION,
    unicode: bool = True
) -> bool:
    
    winsound.MessageBeep(beep)
    res = winuser.MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=winuser.MB_ICONQUESTION | winuser.MB_OKCANCEL | uType, 
        unicode=unicode
    )

    return True if res == winuser.IDOK else False


def askyesno(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = 0, 
    beep: int = winuser.MB_ICONINFORMATION,
    unicode: bool = True
) -> bool:
    
    winsound.MessageBeep(beep)
    res = winuser.MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=winuser.MB_ICONQUESTION | winuser.MB_OKCANCEL | uType, 
        unicode=unicode
    )

    return True if res == winuser.IDOK else False


def askyesnocancel(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = 0, 
    beep: int = winuser.MB_ICONINFORMATION,
    unicode: bool = True
) -> (bool | None):
    
    winsound.MessageBeep(beep)
    res = winuser.MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=winuser.MB_ICONQUESTION | winuser.MB_YESNOCANCEL | uType, 
        unicode=unicode
    )
    
    if res == winuser.IDYES:
        return True
    elif res == winuser.IDNO:
        return False
    return None


def askretrycancel(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = 0, 
    unicode: bool = True
) -> bool:
    
    res = winuser.MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=winuser.MB_ICONWARNING | winuser.MB_RETRYCANCEL | uType, 
        unicode=unicode
    )
    
    return True if res == winuser.IDRETRY else False


