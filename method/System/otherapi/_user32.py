# coding = 'utf-8'

from typing import Any
from method.System.sdkddkver import *
from method.System.winusutypes import *
from method.System.public_dll import user32
from method.System.errcheck import win32_to_errcheck

_WIN32_WINNT = WIN32_WINNT


def CreateWindowInBand(
    dwExStyle: int, 
    lpClassName: str, 
    lpWindowName: str, 
    dwStyle: int, 
    x: int, 
    y: int, 
    nWidth: int, 
    nHeight: int, 
    hWndParent: int, 
    hMenu: int, 
    hInstance: int, 
    lpParam: Any, 
    dwBand: int,
    errcheck: bool = True
) -> int:
    
    CreateWindowInBand = user32.CreateWindowInBand
    CreateWindowInBand.argtypes = [DWORD, LPCWSTR, LPCWSTR, DWORD, INT, INT, INT, INT, HWND, HMENU, HINSTANCE, LPVOID, DWORD]
    CreateWindowInBand.restype = HWND
    res = CreateWindowInBand(
        dwExStyle, 
        lpClassName, 
        lpWindowName, 
        dwStyle, 
        x, 
        y, 
        nWidth, 
        nHeight, 
        hWndParent, 
        hMenu, 
        hInstance, 
        lpParam, 
        dwBand
    )

    return win32_to_errcheck(res, errcheck)



def CreateWindowInBandEx(
    dwExStyle: int, 
    lpClassName: str, 
    lpWindowName: str, 
    dwStyle: int, 
    x: int, 
    y: int, 
    nWidth: int, 
    nHeight: int, 
    hWndParent: int, 
    hMenu: int, 
    hInstance: int, 
    lpParam: Any, 
    dwBand: int,
    dwTypeFlags: int,
    errcheck: bool = True
) -> int:
    
    CreateWindowInBandEx = user32.CreateWindowInBandEx
    CreateWindowInBandEx.argtypes = [DWORD, LPCWSTR, LPCWSTR, DWORD, INT, INT, INT, INT, HWND, HMENU, HINSTANCE, LPVOID, DWORD, DWORD]
    CreateWindowInBandEx.restype = HWND
    res = CreateWindowInBandEx(
        dwExStyle, 
        lpClassName, 
        lpWindowName, 
        dwStyle, 
        x, 
        y, 
        nWidth, 
        nHeight, 
        hWndParent, 
        hMenu, 
        hInstance, 
        lpParam, 
        dwBand,
        dwTypeFlags
    )

    return win32_to_errcheck(res, errcheck)


def GetWindowBand(hwnd: int, pdwBand, errcheck: bool = True):
    GetWindowBand = user32.GetWindowBand
    GetWindowBand.argtypes = [HWND, PDWORD]
    GetWindowBand.restype = BOOL
    res = GetWindowBand(hwnd, pdwBand)
    return win32_to_errcheck(res, errcheck)


def SetWindowBand(hwnd: int, hwndInsertAfter: int, dwBand: int, errcheck: bool = True):
    SetWindowBand = user32.SetWindowBand
    SetWindowBand.argtypes = [HWND, HWND, DWORD]
    SetWindowBand.restype = BOOL
    res = SetWindowBand(hwnd, hwndInsertAfter, dwBand)
    return win32_to_errcheck(res, errcheck)


if _WIN32_WINNT >= WIN32_WINNT_WIN8:
    ZBID_DEFAULT = 0
    ZBID_DESKTOP = 1
    ZBID_UIACCESS = 2
    ZBID_IMMERSIVE_IHM = 3
    ZBID_IMMERSIVE_NOTIFICATION = 4
    ZBID_IMMERSIVE_APPCHROME = 5
    ZBID_IMMERSIVE_MOGO = 6
    ZBID_IMMERSIVE_EDGY = 7
    ZBID_IMMERSIVE_INACTIVEMOBODY = 8
    ZBID_IMMERSIVE_INACTIVEDOCK = 9
    ZBID_IMMERSIVE_ACTIVEMOBODY = 10
    ZBID_IMMERSIVE_ACTIVEDOCK = 11
    ZBID_IMMERSIVE_BACKGROUND = 12
    ZBID_IMMERSIVE_SEARCH = 13
    ZBID_GENUINE_WINDOWS = 14
    ZBID_IMMERSIVE_RESTRICTED = 15
    ZBID_SYSTEM_TOOLS = 16

    # WINDOWS 10+ 
    if _WIN32_WINNT >= WIN32_WINNT_WIN10:
        ZBID_LOCK = 17
        ZBID_ABOVELOCK_UX = 18



def zorder_band_names(zbid: int = NULL) -> str:
    if WIN32_WINNT < WIN32_WINNT_WIN8:
        raise OSError('Do not supported system')
    
    res = {
        "Default": ZBID_DEFAULT,
	    "Desktop": ZBID_DESKTOP,
	    "UIAccess": ZBID_UIACCESS,
	    "Immersive IHM": ZBID_IMMERSIVE_IHM,
	    "Immersive Notification": ZBID_IMMERSIVE_NOTIFICATION,
	    "Immersive AppChrome": ZBID_IMMERSIVE_APPCHROME,
	    "Immersive MoGo": ZBID_IMMERSIVE_MOGO,
	    "Immersive Edgy": ZBID_IMMERSIVE_EDGY,
	    "Immersive InactiveMoBody": ZBID_IMMERSIVE_INACTIVEMOBODY,
	    "Immersive InactiveDock": ZBID_IMMERSIVE_INACTIVEDOCK,
	    "Immersive ActiveMoBody": ZBID_IMMERSIVE_ACTIVEMOBODY,
	    "Immersive ActiveDock": ZBID_IMMERSIVE_ACTIVEDOCK,
	    "Immersive Background": ZBID_IMMERSIVE_BACKGROUND,
	    "Immersive Search": ZBID_IMMERSIVE_SEARCH,
	    "Genuine Windows": ZBID_GENUINE_WINDOWS,
	    "Immersive Restricted": ZBID_IMMERSIVE_RESTRICTED,
	    "System Tools": ZBID_SYSTEM_TOOLS
    }

    # Windows 10+
    if WIN32_WINNT >= WIN32_WINNT_WIN10:
        res["Lock Screen"] = ZBID_LOCK
        res["Above Lock UX"] = ZBID_ABOVELOCK_UX

    for num, j in enumerate(res):
        if num == zbid:
            return j
    raise IndexError('Dict index out of range')

