# coding = 'utf-8'

'''
The messagebox was used Windows API to make. 
Some ways had the messagebox of tkinter in common.
'''

from .windows import *


def showinfo(lpCaption: str = '', 
             lpText: str = '', 
             hwnd: int = HWND(),
             uType: int = NULL, 
             unicode: bool = True) -> bool:
    
    return bool(MessageBox(hwnd=hwnd, 
                           lpCaption=lpCaption, 
                           lpText=lpText, 
                           uType=MB_ICONINFORMATION | uType, 
                           unicode=unicode)
    )


def showwarning(lpCaption: str = '', 
                lpText: str = '', 
                hwnd: int = HWND(),
                uType: int = NULL, 
                unicode: bool = True) -> bool:
    
    return bool(MessageBox(hwnd=hwnd, 
                           lpCaption=lpCaption, 
                           lpText=lpText, 
                           uType=MB_ICONWARNING | uType, 
                           unicode=unicode)
    )


def showerror(lpCaption: str = '', 
              lpText: str = '', 
              hwnd: int = HWND(),
              uType: int = NULL, 
              unicode: bool = True) -> bool:
    
    return bool(MessageBox(hwnd=hwnd, 
                           lpCaption=lpCaption, 
                           lpText=lpText, 
                           uType=MB_ICONERROR | uType, 
                           unicode=unicode)
    )


def askquestion(lpCaption: str = '', 
                lpText: str = '', 
                hwnd: int = HWND(),
                uType: int = NULL, 
                beep: int = MB_ICONINFORMATION,
                unicode: bool = True) -> bool:
    
    MessageBeep(beep)
    return bool(MessageBox(hwnd=hwnd, 
                           lpCaption=lpCaption, 
                           lpText=lpText, 
                           uType=MB_ICONQUESTION | uType, 
                           unicode=unicode)
    )


def askokcancel(lpCaption: str = '', 
                lpText: str = '', 
                hwnd: int = HWND(),
                uType: int = NULL, 
                beep: int = MB_ICONINFORMATION,
                unicode: bool = True) -> bool:
    
    MessageBeep(beep)
    result = MessageBox(hwnd=hwnd, 
                        lpCaption=lpCaption, 
                        lpText=lpText, 
                        uType=MB_ICONQUESTION | MB_OKCANCEL | uType, 
                        unicode=unicode
    )

    return True if result == IDOK else False


def askyesno(lpCaption: str = '', 
             lpText: str = '', 
             hwnd: int = HWND(),
             uType: int = NULL, 
             beep: int = MB_ICONINFORMATION,
             unicode: bool = True) -> bool:
    
    MessageBeep(beep)
    result = MessageBox(hwnd=hwnd, 
                        lpCaption=lpCaption, 
                        lpText=lpText, 
                        uType=MB_ICONQUESTION | MB_OKCANCEL | uType, 
                        unicode=unicode
    )

    return True if result == IDOK else False


def askyesnocancel(lpCaption: str = '', 
                   lpText: str = '', 
                   hwnd: int = HWND(),
                   uType: int = NULL, 
                   beep: int = MB_ICONINFORMATION,
                   unicode: bool = True) -> (bool | None):
    
    MessageBeep(beep)
    result = MessageBox(hwnd=hwnd, 
                        lpCaption=lpCaption, 
                        lpText=lpText, 
                        uType=MB_ICONQUESTION | MB_YESNOCANCEL | uType, 
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
                   uType: int = NULL, 
                   unicode: bool = True) -> bool:
    
    result = MessageBox(hwnd=hwnd, 
                        lpCaption=lpCaption, 
                        lpText=lpText, 
                        uType=MB_ICONWARNING | MB_RETRYCANCEL | uType, 
                        unicode=unicode
    )
    
    return True if result == IDRETRY else False
