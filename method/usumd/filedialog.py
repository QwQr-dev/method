# coding = 'utf-8'

import os
from method.System import shlobj_core
from method.System.winusutypes import *
from method.System.winbase import ZeroMemory
from method.System.commdlg import GetOpenFileName

_askshellfolder_flags = (
    shlobj_core.BIF_DONTGOBELOWDOMAIN | 
    shlobj_core.BIF_RETURNONLYFSDIRS | 
    shlobj_core.BIF_NEWDIALOGSTYLE | 
    shlobj_core.BIF_USENEWUI | 
    shlobj_core.BIF_UAHINT
)

_askopenfilenames_flags = (
    shlobj_core.OFN_FILEMUSTEXIST | 
    shlobj_core.OFN_ALLOWMULTISELECT | 
    shlobj_core.OFN_HIDEREADONLY | 
    shlobj_core.OFN_EXPLORER
)

_askopenfilename_flags = (
    shlobj_core.OFN_FILEMUSTEXIST | 
    shlobj_core.OFN_HIDEREADONLY | 
    shlobj_core.OFN_EXPLORER
)

_asksavefilenames_flags = _askopenfilenames_flags
_asksavefilename_flags = _askopenfilename_flags


def askshellfolder(
    title: str = '', 
    hwnd: int = NULL, 
    pidlRoot: Any = shlobj_core.LPCITEMIDLIST(), 
    pszDisplayName: Any = NULL, 
    ulFlags: int = _askshellfolder_flags, 
    iImage: int = 0
) -> str:
    
    bi = shlobj_core.BROWSEINFOW()
    bi.hwndOwner = hwnd
    bi.pidlRoot = pidlRoot
    bi.pszDisplayName = pszDisplayName
    bi.lpszTitle = title
    bi.ulFlags = ulFlags
    bi.lpfn = shlobj_core.BFFCALLBACK()
    bi.iImage = iImage

    strFolder = (WCHAR * MAX_PATH)()
    pidl = shlobj_core.SHBrowseForFolder(byref(bi))
    shlobj_core.SHGetPathFromIDList(pidl, strFolder)
    return strFolder.value


def lpstrFilter(item: list[tuple[str, str]]) -> str:
    res = []
    for j in item:
        if len(j) != 2:
            raise TypeError('The number of each tuple or list must be 2')
        
        for c in j:
            if not isinstance(c, str):
                raise TypeError(f"The object should be of str, not {type(c).__name__}")
                
            if not c:
                raise TypeError('Elements cannot be empty')

        res.append('\0'.join(j) + '\0')
    return ''.join(res) + '\0'


def _OpenFileName(
    title: str, 
    lpstrFilter: str, 
    hwnd: int, 
    Flags: int, 
    buffer: int, 
    szPath: int, 
    nFilterIndex: int
):
    
    szOpenFileNames = (WCHAR * buffer)()
    szPath = (WCHAR * szPath)()
    ofn = shlobj_core.OPENFILENAMEW()
    ZeroMemory(byref(ofn), sizeof(ofn))
    ofn.lStructSize = sizeof(ofn)
    ofn.hwndOwner = hwnd
    ofn.lpstrFile = cast(szOpenFileNames, LPWSTR)
    ofn.nMaxFile = buffer
    ofn.lpstrFilter = lpstrFilter
    ofn.nFilterIndex = nFilterIndex
    ofn.lpstrTitle = title
    ofn.Flags = Flags
    GetOpenFileName(byref(ofn))
    return szOpenFileNames.value


def _OpenFileNames(
    title: str, 
    lpstrFilter: str, 
    hwnd: int, 
    Flags: int, 
    buffer: int, 
    szPath: int, 
    nFilterIndex: int
):
    
    szOpenFileNames = (WCHAR * buffer)()
    szPath = (WCHAR * szPath)()
    ofn = shlobj_core.OPENFILENAMEW()
    ZeroMemory(byref(ofn), sizeof(ofn))
    ofn.lStructSize = sizeof(ofn)
    ofn.hwndOwner = hwnd
    ofn.lpstrFile = cast(szOpenFileNames, LPWSTR)
    ofn.nMaxFile = buffer
    ofn.lpstrFilter = lpstrFilter
    ofn.nFilterIndex = nFilterIndex
    ofn.lpstrTitle = title
    ofn.Flags = Flags
    GetOpenFileName(byref(ofn))
    path = szOpenFileNames.value
    old_filenames = ''.join(szOpenFileNames)[len(path):].split('\x00')
    new_filenames = []
    if any(old_filenames):
        for c in old_filenames:
            if c: new_filenames.append(c)
        return path, new_filenames
    new_path = os.path.dirname(path)
    new_filenames.append(path[len(new_path) + 1:])
    return new_path, new_filenames


def askopenfilename(
    title: str = '', 
    lpstrFilter: str = '\0', 
    hwnd: int = NULL, 
    Flags: int = _askopenfilename_flags, 
    buffer: int = 2**15, 
    szPath: int = MAX_PATH, 
    nFilterIndex: int = 1
) -> str:
    
    return _OpenFileName(
        title=title,
        lpstrFilter=lpstrFilter,
        hwnd=hwnd,
        Flags=Flags,
        buffer=buffer,
        szPath=szPath,
        nFilterIndex=nFilterIndex
    )


def asksavefilename(
    title: str = '', 
    lpstrFilter: str = '\0', 
    hwnd: int = NULL, 
    Flags: int = _asksavefilename_flags, 
    buffer: int = 2**15, 
    szPath: int = MAX_PATH, 
    nFilterIndex: int = 1
) -> str:
    
    return _OpenFileName(
        title=title,
        lpstrFilter=lpstrFilter,
        hwnd=hwnd,
        Flags=Flags,
        buffer=buffer,
        szPath=szPath,
        nFilterIndex=nFilterIndex
    )


def askopenfilenames(
    title: str = '', 
    lpstrFilter: str = '\0', 
    hwnd: int = NULL, 
    Flags: int = _askopenfilenames_flags, 
    buffer: int = 2**15, 
    szPath: int = MAX_PATH, 
    nFilterIndex: int = 1
) -> tuple[str, list[str]]:
    
    return _OpenFileNames(
        title=title,
        lpstrFilter=lpstrFilter,
        hwnd=hwnd,
        Flags=Flags,
        buffer=buffer,
        szPath=szPath,
        nFilterIndex=nFilterIndex
    )


def asksavefilenames(
    title: str = '', 
    lpstrFilter: str = '\0', 
    hwnd: int = NULL, 
    Flags: int = _asksavefilenames_flags, 
    buffer: int = 2**15, 
    szPath: int = MAX_PATH, 
    nFilterIndex: int = 1, 
) -> tuple[str, list[str]]:
    
    return _OpenFileNames(
        title=title,
        lpstrFilter=lpstrFilter,
        hwnd=hwnd,
        Flags=Flags,
        buffer=buffer,
        szPath=szPath,
        nFilterIndex=nFilterIndex
    )


if __name__ == '__main__':
    # test

    lpstrFilters = lpstrFilter([('All', '*.*'), 
                                ('.h', '*.h'), 
                                ('.c', '*.c'), 
                                ('.cpp', '*.cpp'), 
                                ('.py', '*.py')
                    ]
    )

    res = askopenfilename(lpstrFilter = lpstrFilters)
    print(res)

    res = asksavefilename(lpstrFilter = lpstrFilters)
    print(res)

    res = askopenfilenames(lpstrFilter = lpstrFilters)
    print(res)

    res = asksavefilenames(lpstrFilter = lpstrFilters)
    print(res)
    