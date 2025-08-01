# coding = 'utf-8'

''' The TaskDialogIndirect was used Windows API to make. '''

import ctypes
from typing import Any

try:
    from .windows import *
except ImportError:
    from windows import *
    
    
GetLastError = Kernel32.GetLastError


def TaskDialog(hwndOwner: int = HWND(), 
               hInstance: int = HINSTANCE(), 
               pszWindowTitle: str = PCWSTR(), 
               pszMainInstruction: str = PCWSTR(), 
               pszContent: str = PCWSTR(), 
               dwCommonButtons: int = TASKDIALOG_COMMON_BUTTON_FLAGS(), 
               pszIcon: int = PCWSTR()) -> int:

    pnButton = INT()
    _TaskDialog = comctl32.TaskDialog
    error_code = _TaskDialog(hwndOwner, 
                             hInstance,
                             pszWindowTitle,
                             pszMainInstruction,
                             pszContent,
                             dwCommonButtons, 
                             pszIcon,
                             ctypes.byref(pnButton)
    )

    pnButton = pnButton.value

    if error_code != S_OK:
        raise ctypes.WinError(error_code)
    return pnButton


def TaskDialogIndirect(hwndParent: int = HWND(), 
                       hInstance: int = HINSTANCE(), 
                       dwFlags: int = TASKDIALOG_FLAGS(), 
                       dwCommonButtons: int = TASKDIALOG_COMMON_BUTTON_FLAGS(), 
                       pszWindowTitle: str = '', 
                       hMainIcon: int = HICON(), 
                       pszMainIcon: str = PCWSTR(), 
                       pszMainInstruction: str = '', 
                       pszContent: str = '', 
                       Buttons: list | tuple = None, 
                       nDefaultButton: int = INT(), 
                       RadioButtons: list | tuple = None, 
                       nDefaultRadioButton: int = INT(), 
                       pszVerificationText: str = '',
                       pszExpandedInformation: str = '', 
                       pszExpandedControlText: str = '', 
                       pszCollapsedControlText: str = '', 
                       FooterIcon: Any = TASKDIALOGFOOTICON(), 
                       pszFooter: str = PCWSTR(), 
                       pfCallback: Any = PFTASKDIALOGCALLBACK(), 
                       lpCallbackData: int = LONG_PTR(), 
                       cxWidth: int = UINT()) -> dict:
    
    config = TASKDIALOGCONFIG()
    config.cbSize = ctypes.sizeof(config)
    config.hwndParent = hwndParent
    config.hInstance = hInstance
    config.dwFlags = dwFlags
    config.dwCommonButtons = dwCommonButtons
    config.pszWindowTitle = pszWindowTitle
    config.MainIcon.hMainIcon = hMainIcon
    config.MainIcon.pszMainIcon = ctypes.cast(pszMainIcon, PCWSTR)
    config.pszMainInstruction = pszMainInstruction
    config.pszContent = pszContent

    if Buttons is not None:
        button_array = (TASKDIALOG_BUTTON * len(Buttons))(*Buttons)
        config.cButtons = len(Buttons)
        config.pButtons = ctypes.cast(button_array, ctypes.POINTER(TASKDIALOG_BUTTON))

    config.nDefaultButton = nDefaultButton

    if RadioButtons is not None:
        RadioButton_array = (TASKDIALOG_BUTTON * len(RadioButtons))(*RadioButtons)
        config.cRadioButtons = len(RadioButtons)
        config.pRadioButtons = ctypes.cast(RadioButton_array, ctypes.POINTER(TASKDIALOG_BUTTON))

    config.nDefaultRadioButton = nDefaultRadioButton
    config.pszVerificationText = pszVerificationText
    config.pszExpandedInformation = pszExpandedInformation
    config.pszExpandedControlText = pszExpandedControlText
    config.pszCollapsedControlText = pszCollapsedControlText
    config.FooterIcon = FooterIcon
    config.pszFooter = pszFooter
    config.pfCallback = pfCallback
    config.lpCallbackData = lpCallbackData
    config.cxWidth = cxWidth

    pnButton = INT()
    pnRadioButton = INT()
    pfVerificationFlagChecked = BOOL()
    _TaskDialogIndirect = comctl32.TaskDialogIndirect
    error_code = _TaskDialogIndirect(ctypes.byref(config), 
                                     ctypes.byref(pnButton),  
                                     ctypes.byref(pnRadioButton), 
                                     ctypes.byref(pfVerificationFlagChecked)
    )
    
    if error_code != S_OK:
        raise ctypes.WinError(error_code)
    
    result = {}
    result['pnButton'] = pnButton.value
    result['pnRadioButton'] = pnRadioButton.value
    result['pfVerificationFlagChecked'] = pfVerificationFlagChecked.value
    return result


if __name__ == '__main__':
    # test

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
                             RadioButtons=[TASKDIALOG_BUTTON(2000, '选项1'), TASKDIALOG_BUTTON(2001, '选项2')], 
                             pszVerificationText='I agree.')
    )

