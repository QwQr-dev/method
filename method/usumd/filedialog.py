# coding = 'utf-8'

import os

from method.System.commdlg import *
from method.System.shlobj_core import *
from method.System.winnt import ZeroMemory

_SupportTypes = list[tuple[str, str]]

askshellfolder_flags = (BIF_DONTGOBELOWDOMAIN | 
                        BIF_RETURNONLYFSDIRS | 
                        BIF_NEWDIALOGSTYLE | 
                        BIF_USENEWUI | 
                        BIF_UAHINT
)

askopenfilenames_flags = (OFN_FILEMUSTEXIST | 
                          OFN_ALLOWMULTISELECT | 
                          OFN_HIDEREADONLY | 
                          OFN_EXPLORER
)

askopenfilename_flags = (OFN_FILEMUSTEXIST | 
                         OFN_HIDEREADONLY | 
                         OFN_EXPLORER
)

asksavefilenames_flags = askopenfilenames_flags
asksavefilename_flags = askopenfilename_flags


def askshellfolder(
    title: str | bytes = '', 
    hwnd: int = NULL, 
    pidlRoot: Any = LPCITEMIDLIST(), 
    pszDisplayName: Any = NULL, 
    ulFlags: int = askshellfolder_flags, 
    iImage: int = 0,
    unicode: bool = True
) -> (str | bytes):
    
    bi = (BROWSEINFOW if unicode else BROWSEINFOA)()
    bi.hwndOwner = hwnd
    bi.pidlRoot = pidlRoot
    bi.pszDisplayName = pszDisplayName
    bi.lpszTitle = title
    bi.ulFlags = ulFlags
    bi.lpfn = BFFCALLBACK()
    bi.iImage = iImage

    strFolder = ((WCHAR if unicode else CHAR) * MAX_PATH)()
    pidl = SHBrowseForFolder(byref(bi), unicode=unicode)
    strFolder = SHGetPathFromIDList(pidl, strFolder, unicode=unicode)
    return strFolder.value


def lpstrFilter(item: _SupportTypes) -> str:
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


def askopenfilename(
    title: str | bytes = '', 
    lpstrFilter: str | bytes = '\0', 
    hwnd: int = NULL, 
    Flags: int = askopenfilename_flags, 
    buffer: int = 2**15-1, 
    szPath: int = MAX_PATH, 
    nFilterIndex: int = 1, 
    unicode: bool = True
) -> (str | bytes):
    
    szOpenFileNames = ((WCHAR if unicode else CHAR) * buffer)()
    szPath = ((WCHAR if unicode else CHAR) * szPath)()

    ofn = (OPENFILENAMEW if unicode else OPENFILENAMEA)()
    ZeroMemory(byref(ofn), sizeof(ofn))

    ofn.lStructSize = sizeof(ofn)
    ofn.hwndOwner = hwnd
    ofn.lpstrFile = cast(szOpenFileNames, LPWSTR if unicode else LPSTR)
    ofn.nMaxFile = buffer
    ofn.lpstrFilter = lpstrFilter
    ofn.nFilterIndex = nFilterIndex
    ofn.lpstrTitle = title
    ofn.Flags = Flags

    GetOpenFileName(byref(ofn), unicode=unicode)
    return szOpenFileNames.value


def asksavefilename(
    title: str | bytes = '', 
    lpstrFilter: str | bytes = '\0', 
    hwnd: int = NULL, 
    Flags: int = asksavefilename_flags, 
    buffer: int = 2**15-1, 
    szPath: int = MAX_PATH, 
    nFilterIndex: int = 1, 
    unicode: bool = True
) -> (str | bytes):
    
    szOpenFileNames = ((WCHAR if unicode else CHAR) * buffer)()
    szPath = ((WCHAR if unicode else CHAR) * szPath)()

    ofn = (OPENFILENAMEW if unicode else OPENFILENAMEA)()
    ZeroMemory(byref(ofn), sizeof(ofn))

    ofn.lStructSize = sizeof(ofn)
    ofn.hwndOwner = hwnd
    ofn.lpstrFile = cast(szOpenFileNames, LPWSTR if unicode else LPSTR)
    ofn.nMaxFile = buffer
    ofn.lpstrFilter = lpstrFilter
    ofn.nFilterIndex = nFilterIndex
    ofn.lpstrTitle = title
    ofn.Flags = Flags

    GetSaveFileName(byref(ofn), unicode=unicode)
    return szOpenFileNames.value


def askopenfilenames(
    title: str | bytes = '', 
    lpstrFilter: str | bytes = '\0', 
    hwnd: int = NULL, 
    Flags: int = askopenfilenames_flags, 
    buffer: int = 2**15-1, 
    szPath: int = MAX_PATH, 
    nFilterIndex: int = 1, 
    unicode: bool = True
) -> tuple[str | bytes, list[str | bytes]]:
    
    szOpenFileNames = ((WCHAR if unicode else CHAR) * buffer)()
    szPath = ((WCHAR if unicode else CHAR) * szPath)()

    ofn = (OPENFILENAMEW if unicode else OPENFILENAMEA)()
    ZeroMemory(byref(ofn), sizeof(ofn))

    ofn.lStructSize = sizeof(ofn)
    ofn.hwndOwner = hwnd
    ofn.lpstrFile = cast(szOpenFileNames, LPWSTR if unicode else LPSTR)
    ofn.nMaxFile = buffer
    ofn.lpstrFilter = lpstrFilter
    ofn.nFilterIndex = nFilterIndex
    ofn.lpstrTitle = title
    ofn.Flags = Flags

    GetOpenFileName(byref(ofn), unicode=unicode)

    num = 0
    res = []
    for j in szOpenFileNames:
        try:
            if szOpenFileNames[num] == '\0' and szOpenFileNames[num + 1] == '\0' and unicode:
                break
            elif szOpenFileNames[num] == b'\0' and szOpenFileNames[num + 1] == b'\0':
                break
            res.append(j)
            num += 1
        except:
            break

    res = ('' if unicode else b'').join(res).split('\0' if unicode else b'\0')

    if len(res) > 1:
        path = res[0]
        res.remove(res[0])
    else:
        path = os.path.dirname(res[0])
        res.append(os.path.basename(res[0]))
        res.remove(res[0])

    return path, res


def asksavefilenames(
    title: str | bytes = '', 
    lpstrFilter: str | bytes = '\0', 
    hwnd: int = NULL, 
    Flags: int = asksavefilenames_flags, 
    buffer: int = 2**15-1, 
    szPath: int = MAX_PATH, 
    nFilterIndex: int = 1, 
    unicode: bool = True
) -> tuple[str | bytes, list[str | bytes]]:
    
    szOpenFileNames = ((WCHAR if unicode else CHAR) * buffer)()
    szPath = ((WCHAR if unicode else CHAR) * szPath)()

    ofn = (OPENFILENAMEW if unicode else OPENFILENAMEA)()
    ZeroMemory(byref(ofn), sizeof(ofn))

    ofn.lStructSize = sizeof(ofn)
    ofn.hwndOwner = hwnd
    ofn.lpstrFile = cast(szOpenFileNames, LPWSTR if unicode else LPSTR)
    ofn.nMaxFile = buffer
    ofn.lpstrFilter = lpstrFilter
    ofn.nFilterIndex = nFilterIndex
    ofn.lpstrTitle = title
    ofn.Flags = Flags

    GetSaveFileName(byref(ofn), unicode=unicode)

    num = 0
    res = []
    for j in szOpenFileNames:
        try:
            if szOpenFileNames[num] == '\0' and szOpenFileNames[num + 1] == '\0' and unicode:
                break
            elif szOpenFileNames[num] == b'\0' and szOpenFileNames[num + 1] == b'\0':
                break
            res.append(j)
            num += 1
        except:
            break

    res = ('' if unicode else b'').join(res).split('\0' if unicode else b'\0')

    if len(res) > 1:
        path = res[0]
        res.remove(res[0])
    else:
        path = os.path.dirname(res[0])
        res.append(os.path.basename(res[0]))
        res.remove(res[0])
        
    return path, res


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
    