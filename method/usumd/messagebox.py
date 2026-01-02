# coding = 'utf-8'

'''
The messagebox was used Windows API to make. 
Some ways had the messagebox of tkinter in common.
'''

from method.System.windows import *


def showinfo(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = NULL, 
    unicode: bool = True
) -> bool:
    
    return bool(MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=MB_ICONINFORMATION | uType, 
        unicode=unicode)
    )


def showwarning(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = NULL, 
    unicode: bool = True
) -> bool:
    
    return bool(MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=MB_ICONWARNING | uType, 
        unicode=unicode)
    )


def showerror(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = NULL, 
    unicode: bool = True
) -> bool:
    
    return bool(MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=MB_ICONERROR | uType, 
        unicode=unicode)
    )


def askquestion(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = NULL, 
    beep: int = MB_ICONINFORMATION,
    unicode: bool = True
) -> bool:
    
    MessageBeep(beep)
    return bool(MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=MB_ICONQUESTION | uType, 
        unicode=unicode)
    )


def askokcancel(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = NULL, 
    beep: int = MB_ICONINFORMATION,
    unicode: bool = True
) -> bool:
    
    MessageBeep(beep)
    res = MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=MB_ICONQUESTION | MB_OKCANCEL | uType, 
        unicode=unicode
    )

    return True if res == IDOK else False


def askyesno(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = NULL, 
    beep: int = MB_ICONINFORMATION,
    unicode: bool = True
) -> bool:
    
    MessageBeep(beep)
    res = MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=MB_ICONQUESTION | MB_OKCANCEL | uType, 
        unicode=unicode
    )

    return True if res == IDOK else False


def askyesnocancel(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = NULL, 
    beep: int = MB_ICONINFORMATION,
    unicode: bool = True
) -> (bool | None):
    
    MessageBeep(beep)
    res = MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=MB_ICONQUESTION | MB_YESNOCANCEL | uType, 
        unicode=unicode
    )
    
    if res == IDYES:
        return True
    elif res == IDNO:
        return False
    return None


def askretrycancel(
    lpCaption: str = '', 
    lpText: str = '', 
    hwnd: int = NULL,
    uType: int = NULL, 
    unicode: bool = True
) -> bool:
    
    res = MessageBox(
        hwnd=hwnd, 
        lpCaption=str(lpCaption), 
        lpText=str(lpText), 
        uType=MB_ICONWARNING | MB_RETRYCANCEL | uType, 
        unicode=unicode
    )
    
    return True if res == IDRETRY else False
