# coding = 'utf-8'

from method.System.winusutypes import *
from method.System.public_dll import shell32

RFD_NOBROWSE            = 0x00000001
RFD_NODEFFILE           = 0x00000002
RFD_USEFULLPATHDIR      = 0x00000004
RFD_NOSHOWOPEN          = 0x00000008
RFD_WOW_APP             = 0x00000010
RFD_NOSEPMEMORY_BOX     = 0x00000020


def RunfileDlg(
    hwndOwner: int, 
    hIcon: int, 
    lpszDirectory: str, 
    lpszTitle: str, 
    lpszDescription: str, 
    uFlags: int = RFD_USEFULLPATHDIR | RFD_WOW_APP,
    unicode: bool = True,
    index: int = 61
) -> None:      # “运行”对话框
    
    RUNFILEDLG = WINAPI(
        VOID, 
        HWND, 
        HICON, 
        (LPCWSTR if unicode else LPSTR), 
        (LPCWSTR if unicode else LPSTR), 
        (LPCWSTR if unicode else LPSTR), 
        UINT
    )

    RunfileDlg = RUNFILEDLG(shell32[index])
    RunfileDlg(hwndOwner, hIcon, lpszDirectory, lpszTitle, lpszDescription, uFlags)