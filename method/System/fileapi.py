# coding = 'utf-8'
# fileapi.h

from method.System.errcheck import *
from method.System.minwindef import *
from method.System.minwinbase import *
from method.System.public_dll import *
from method.System.winusutypes import *

CREATE_NEW = 1
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
TRUNCATE_EXISTING = 5

INVALID_FILE_SIZE = DWORD(0xffffffff).value
INVALID_SET_FILE_POINTER = DWORD(-1).value
INVALID_FILE_ATTRIBUTES = DWORD(-1).value

class _BY_HANDLE_FILE_INFORMATION(Structure):
    _fields_ = [
        ('dwFileAttributes', DWORD),
        ('ftCreationTime', FILETIME),
        ('ftLastAccessTime', FILETIME),
        ('ftLastWriteTime', FILETIME),
        ('dwVolumeSerialNumber', DWORD),
        ('nFileSizeHigh', DWORD),
        ('nFileSizeLow', DWORD),
        ('nNumberOfLinks', DWORD),
        ('nFileIndexHigh', DWORD),
        ('nFileIndexLow', DWORD)
    ]

BY_HANDLE_FILE_INFORMATION = _BY_HANDLE_FILE_INFORMATION
PBY_HANDLE_FILE_INFORMATION = POINTER(BY_HANDLE_FILE_INFORMATION)
LPBY_HANDLE_FILE_INFORMATION = PBY_HANDLE_FILE_INFORMATION

def GetFileInformationByHandle(hFile, lpFileInformation, errcheck: bool = True):
    GetFileInformationByHandle = kernel32.GetFileInformationByHandle
    GetFileInformationByHandle.argtypes = [HANDLE, LPBY_HANDLE_FILE_INFORMATION]
    GetFileInformationByHandle.restype = WINBOOL
    res = GetFileInformationByHandle(hFile, lpFileInformation)
    return win32_to_errcheck(res, errcheck)


def CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, unicode: bool = True):
    CreateFile = kernel32.CreateFileW if unicode else kernel32.CreateFileA
    CreateFile.argtypes = [(LPCWSTR if unicode else LPCSTR), DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE]
    CreateFile.restype = HANDLE
    res = CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
    return res


def DefineDosDevice(dwFlags, lpDeviceName, lpTargetPath, unicode: bool = True, errcheck: bool = True):
    DefineDosDevice = kernel32.DefineDosDeviceW if unicode else kernel32.DefineDosDeviceA
    DefineDosDevice.argtypes = [DWORD, (LPCWSTR if unicode else LPCSTR), (LPCWSTR if unicode else LPCSTR)]
    DefineDosDevice.restype = WINBOOL
    res = DefineDosDevice(dwFlags, lpDeviceName, lpTargetPath)
    return win32_to_errcheck(res, errcheck)


def FindCloseChangeNotification(hChangeHandle, errcheck: bool = True):
    FindCloseChangeNotification = kernel32.FindCloseChangeNotification
    FindCloseChangeNotification.argtypes = [HANDLE]
    FindCloseChangeNotification.restype = WINBOOL
    res = FindCloseChangeNotification(hChangeHandle)
    return win32_to_errcheck(res, errcheck)


def FindFirstChangeNotification(lpPathName, bWatchSubtree, dwNotifyFilter, unicode: bool = True):
    FindFirstChangeNotification = kernel32.FindFirstChangeNotificationW if unicode else kernel32.FindFirstChangeNotificationA
    FindFirstChangeNotification.argtypes = [(LPCWSTR if unicode else LPCSTR), WINBOOL, DWORD]
    FindFirstChangeNotification.restype = HANDLE
    res = FindFirstChangeNotification(lpPathName, bWatchSubtree, dwNotifyFilter)
    return res


def FindFirstChangeNotification(lpPathName, bWatchSubtree, dwNotifyFilter, unicode: bool = True):
    FindFirstChangeNotification = kernel32.FindFirstChangeNotificationW if unicode else kernel32.FindFirstChangeNotificationA
    FindFirstChangeNotification.argtypes = [(LPCWSTR if unicode else LPCSTR), WINBOOL, DWORD]
    FindFirstChangeNotification.restype = HANDLE
    res = FindFirstChangeNotification(lpPathName, bWatchSubtree, dwNotifyFilter)
    return res


def FindFirstVolume(lpszVolumeName, cchBufferLength, unicode: bool = True):
    FindFirstVolume = kernel32.FindFirstVolumeW if unicode else kernel32.FindFirstVolumeA
    FindFirstVolume.argtypes = [(LPWSTR if unicode else LPSTR), DWORD]
    FindFirstVolume.restype = HANDLE
    res = FindFirstVolume(lpszVolumeName, cchBufferLength)
    return res


def FindNextChangeNotification(hChangeHandle, errcheck: bool = True):
    FindNextChangeNotification = kernel32.FindNextChangeNotification
    FindNextChangeNotification.argtypes = [HANDLE]
    FindNextChangeNotification.restype = WINBOOL
    res = FindNextChangeNotification(hChangeHandle)
    return win32_to_errcheck(res, errcheck)


def FindNextVolume(hFindVolume, lpszVolumeName, cchBufferLength, unicode: bool = True, errcheck: bool = True):
    FindNextVolume = kernel32.FindNextVolumeW if unicode else kernel32.FindNextVolumeA
    FindNextVolume.argtypes = [HANDLE, (LPWSTR if unicode else LPSTR), DWORD]
    FindNextVolume.restype = WINBOOL
    res = FindNextVolume(hFindVolume, lpszVolumeName, cchBufferLength)
    return win32_to_errcheck(res, errcheck)


def FindVolumeClose(hFindVolume, errcheck: bool = True):
    FindVolumeClose = kernel32.FindVolumeClose
    FindVolumeClose.argtypes = [HANDLE]
    FindVolumeClose.restype = WINBOOL
    res = FindVolumeClose(hFindVolume)
    return win32_to_errcheck(res, errcheck)


def GetFileSize(hFile, lpFileSizeHigh):
    GetFileSize = kernel32.GetFileSize
    GetFileSize.argtypes = [HANDLE, LPDWORD]
    GetFileSize.restype = DWORD
    res = GetFileSize(hFile, lpFileSizeHigh)
    return res


def CompareFileTime(lpFileTime1, lpFileTime2, errcheck: bool = True):
    CompareFileTime = kernel32.CompareFileTime
    CompareFileTime.argtypes = [POINTER(FILETIME), POINTER(FILETIME)]
    CompareFileTime.restype = LONG
    res = CompareFileTime(lpFileTime1, lpFileTime2)
    return hresult_to_errcheck(res, errcheck)


def DeleteVolumeMountPoint(lpszVolumeMountPoint, unicode: bool = True, errcheck: bool = True):
    DeleteVolumeMountPoint = kernel32.DeleteVolumeMountPointW if unicode else kernel32.DeleteVolumeMountPointA
    DeleteVolumeMountPoint.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    DeleteVolumeMountPoint.restype = WINBOOL
    res = DeleteVolumeMountPoint(lpszVolumeMountPoint)
    return win32_to_errcheck(res, errcheck)


def FileTimeToLocalFileTime(lpFileTime, lpLocalFileTime, errcheck: bool = True):
    FileTimeToLocalFileTime = kernel32.FileTimeToLocalFileTime
    FileTimeToLocalFileTime.argtypes = [POINTER(FILETIME), LPFILETIME]
    FileTimeToLocalFileTime.restype = WINBOOL
    res = FileTimeToLocalFileTime(lpFileTime, lpLocalFileTime)
    return win32_to_errcheck(res, errcheck)


def FindFirstFile(lpFileName, lpFindFileData, unicode: bool = True):
    FindFirstFile = kernel32.FindFirstFileW if unicode else kernel32.FindFirstFileA
    FindFirstFile.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPWIN32_FIND_DATAW if unicode else LPWIN32_FIND_DATAA)]
    FindFirstFile.restype = HANDLE
    res = FindFirstFile(lpFileName, lpFindFileData)
    return res


def GetDiskFreeSpace(lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters, unicode: bool = True, errcheck: bool = True):      
    GetDiskFreeSpace = kernel32.GetDiskFreeSpaceW if unicode else kernel32.GetDiskFreeSpaceA
    GetDiskFreeSpace.argtypes = [(LPCWSTR if unicode else LPCSTR), LPDWORD, LPDWORD, LPDWORD, LPDWORD]
    GetDiskFreeSpace.restype = WINBOOL
    res = GetDiskFreeSpace(lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters)
    return win32_to_errcheck(res, errcheck)


def GetDriveType(lpRootPathName, unicode: bool = True, errcheck: bool = True):
    GetDriveType = kernel32.GetDriveTypeW if unicode else kernel32.GetDriveTypeA
    GetDriveType.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    GetDriveType.restype = UINT
    res = GetDriveType(lpRootPathName)
    return win32_to_errcheck(res, errcheck)


def GetFileAttributes(lpFileName, unicode: bool = True):
    GetFileAttributes = kernel32.GetFileAttributesW if unicode else kernel32.GetFileAttributesA
    GetFileAttributes.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    GetFileAttributes.restype = DWORD
    res = GetFileAttributes(lpFileName)
    return res


def GetFileSizeEx(hFile, lpFileSize, errcheck: bool = True):
    GetFileSizeEx = kernel32.GetFileSizeEx
    GetFileSizeEx.argtypes = [HANDLE, PLARGE_INTEGER]
    GetFileSizeEx.restype = WINBOOL
    res = GetFileSizeEx(hFile, lpFileSize)
    return win32_to_errcheck(res, errcheck)


def GetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime, errcheck: bool = True):
    GetFileTime = kernel32.GetFileTime
    GetFileTime.argtypes = [HANDLE, LPFILETIME, LPFILETIME, LPFILETIME]
    GetFileTime.restype = WINBOOL
    res = GetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime)
    return win32_to_errcheck(res, errcheck)


def GetFileType(hFile):
    GetFileType = kernel32.GetFileType
    GetFileType.argtypes = [HANDLE]
    GetFileType.restype = DWORD
    res = GetFileType(hFile)
    return res


def GetFullPathName(lpFileName, nBufferLength, lpBuffer, lpFilePart, unicode: bool = True):
    GetFullPathName = kernel32.GetFullPathNameW if unicode else kernel32.GetFullPathNameA
    GetFullPathName.argtypes = [(LPCWSTR if unicode else LPCSTR), DWORD, (LPWSTR if unicode else LPSTR), POINTER(LPSTR)]
    GetFullPathName.restype = DWORD
    res = GetFullPathName(lpFileName, nBufferLength, lpBuffer, lpFilePart)
    return res


def GetLogicalDrives():
    GetLogicalDrives = kernel32.GetLogicalDrives

    GetLogicalDrives.restype = DWORD
    res = GetLogicalDrives()
    return res


def GetVolumeNameForVolumeMountPoint(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength, unicode: bool = True, errcheck: bool = True):
    GetVolumeNameForVolumeMountPoint = kernel32.GetVolumeNameForVolumeMountPointW if unicode else kernel32.GetVolumeNameForVolumeMountPointA
    GetVolumeNameForVolumeMountPoint.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPWSTR if unicode else LPSTR), DWORD]
    GetVolumeNameForVolumeMountPoint.restype = WINBOOL
    res = GetVolumeNameForVolumeMountPoint(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)
    return win32_to_errcheck(res, errcheck)


def GetVolumePathName(lpszFileName, lpszVolumePathName, cchBufferLength, unicode: bool = True, errcheck: bool = True):
    GetVolumePathName = kernel32.GetVolumePathNameW if unicode else kernel32.GetVolumePathNameA
    GetVolumePathName.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPWSTR if unicode else LPSTR), DWORD]
    GetVolumePathName.restype = WINBOOL
    res = GetVolumePathName(lpszFileName, lpszVolumePathName, cchBufferLength)
    return win32_to_errcheck(res, errcheck)


def ReadFileScatter(hFile, aSegmentArray, nNumberOfBytesToRead, lpReserved, lpOverlapped, errcheck: bool = True):
    ReadFileScatter = kernel32.ReadFileScatter
    ReadFileScatter.argtypes = [HANDLE, FILE_SEGMENT_ELEMENT, DWORD, LPDWORD, LPOVERLAPPED]
    ReadFileScatter.restype = WINBOOL
    res = ReadFileScatter(hFile, aSegmentArray, nNumberOfBytesToRead, lpReserved, lpOverlapped)
    return win32_to_errcheck(res, errcheck)


def SetFileValidData(hFile, ValidDataLength, errcheck: bool = True):
    SetFileValidData = kernel32.SetFileValidData
    SetFileValidData.argtypes = [HANDLE, LONGLONG]
    SetFileValidData.restype = WINBOOL
    res = SetFileValidData(hFile, ValidDataLength)
    return win32_to_errcheck(res, errcheck)


def WriteFileGather(hFile, aSegmentArray, nNumberOfBytesToWrite, lpReserved, lpOverlapped, errcheck: bool = True):
    WriteFileGather = kernel32.WriteFileGather
    WriteFileGather.argtypes = [HANDLE, FILE_SEGMENT_ELEMENT, DWORD, LPDWORD, LPOVERLAPPED]
    WriteFileGather.restype = WINBOOL
    res = WriteFileGather(hFile, aSegmentArray, nNumberOfBytesToWrite, lpReserved, lpOverlapped)
    return win32_to_errcheck(res, errcheck)


def GetLogicalDriveStrings(nBufferLength: int, lpBuffer, unicode: bool = True, errcheck: bool = True):
    GetLogicalDriveStrings = kernel32.GetLogicalDriveStringsW if unicode else kernel32.GetLogicalDriveStringsA
    GetLogicalDriveStrings.argtypes = [
        DWORD,
        (LPWSTR if unicode else LPSTR)
    ]

    GetLogicalDriveStrings.restype = DWORD
    res = GetLogicalDriveStrings(nBufferLength, lpBuffer)
    return win32_to_errcheck(res, errcheck)



def GetShortPathName(lpszLongPath, lpszShortPath, cchBuffer, unicode: bool = True):
    GetShortPathName = kernel32.GetShortPathNameW if unicode else kernel32.GetShortPathNameA
    GetShortPathName.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPWSTR if unicode else LPSTR), DWORD]
    GetShortPathName.restype = DWORD
    res = GetShortPathName(lpszLongPath, lpszShortPath, cchBuffer)
    return res


def QueryDosDevice(
    lpDeviceName: str | bytes, 
    lpTargetPath: Array[c_wchar] | Array[c_char], 
    ucchMax: int, 
    unicode: bool = True, 
    errcheck: bool = True
):
    
    QueryDosDevice = kernel32.QueryDosDeviceW if unicode else kernel32.QueryDosDeviceA
    QueryDosDevice.argtypes = [
        (LPCWSTR if unicode else LPCSTR), 
        (LPWSTR if unicode else LPSTR), 
        DWORD
    ]

    QueryDosDevice.restype = DWORD
    res = QueryDosDevice(lpDeviceName, lpTargetPath, ucchMax)
    return win32_to_errcheck(res, errcheck)


def GetVolumePathNamesForVolumeName(lpszVolumeName, lpszVolumePathNames, cchBufferLength, lpcchReturnLength, unicode: bool = True, errcheck: bool = True):
    GetVolumePathNamesForVolumeName = kernel32.GetVolumePathNamesForVolumeNameW if unicode else kernel32.GetVolumePathNamesForVolumeNameA
    GetVolumePathNamesForVolumeName.argtypes = [(LPCWSTR if unicode else LPCSTR), LPWCH, DWORD, PDWORD]
    GetVolumePathNamesForVolumeName.restype = WINBOOL
    res = GetVolumePathNamesForVolumeName(lpszVolumeName, lpszVolumePathNames, cchBufferLength, lpcchReturnLength)
    return win32_to_errcheck(res, errcheck)


def GetVolumeInformationByHandle(hFile, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize, unicode: bool = True, errcheck: bool = True):
    GetVolumeInformationByHandle = kernel32.GetVolumeInformationByHandleW if unicode else kernel32.GetVolumeInformationByHandleA
    GetVolumeInformationByHandle.argtypes = [HANDLE, (LPWSTR if unicode else LPSTR), DWORD, LPDWORD, LPDWORD, LPDWORD, (LPWSTR if unicode else LPSTR), DWORD]
    GetVolumeInformationByHandle.restype = WINBOOL
    res = GetVolumeInformationByHandle(hFile, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)
    return win32_to_errcheck(res, errcheck)


def AreShortNamesEnabled(Handle, Enabled, errcheck: bool = True):
    AreShortNamesEnabled = kernel32.AreShortNamesEnabled
    AreShortNamesEnabled.argtypes = [HANDLE, POINTER(WINBOOL)]
    AreShortNamesEnabled.restype = WINBOOL
    res = AreShortNamesEnabled(Handle, Enabled)
    return win32_to_errcheck(res, errcheck)


def GetLongPathName(lpszShortPath, lpszLongPath, cchBuffer, unicode: bool = True):
    GetLongPathName = kernel32.GetLongPathNameW if unicode else kernel32.GetLongPathNameA
    GetLongPathName.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPWSTR if unicode else LPSTR), DWORD]
    GetLongPathName.restype = DWORD
    res = GetLongPathName(lpszShortPath, lpszLongPath, cchBuffer)
    return res


def GetTempFileName(lpPathName, lpPrefixString, uUnique, lpTempFileName, unicode: bool = True, errcheck: bool = True):
    GetTempFileName = kernel32.GetTempFileNameW if unicode else kernel32.GetTempFileNameA
    GetTempFileName.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPCWSTR if unicode else LPCSTR), UINT, (LPWSTR if unicode else LPSTR)]
    GetTempFileName.restype = UINT
    res = GetTempFileName(lpPathName, lpPrefixString, uUnique, lpTempFileName)
    return win32_to_errcheck(res, errcheck)


def GetVolumeInformation(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize, unicode: bool = True, errcheck: bool = True):
    GetVolumeInformation = kernel32.GetVolumeInformationW if unicode else kernel32.GetVolumeInformationA
    GetVolumeInformation.argtypes = [(LPCWSTR if unicode else LPCSTR), (LPWSTR if unicode else LPSTR), DWORD, LPDWORD, LPDWORD, LPDWORD, (LPWSTR if unicode else LPSTR), DWORD] 
    GetVolumeInformation.restype = WINBOOL
    res = GetVolumeInformation(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)
    return win32_to_errcheck(res, errcheck)


def LocalFileTimeToFileTime(lpLocalFileTime, lpFileTime, errcheck: bool = True):
    LocalFileTimeToFileTime = kernel32.LocalFileTimeToFileTime
    LocalFileTimeToFileTime.argtypes = [POINTER(FILETIME), LPFILETIME]
    LocalFileTimeToFileTime.restype = WINBOOL
    res = LocalFileTimeToFileTime(lpLocalFileTime, lpFileTime)
    return win32_to_errcheck(res, errcheck)


def LockFile(hFile, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh, errcheck: bool = True):
    LockFile = kernel32.LockFile
    LockFile.argtypes = [HANDLE, DWORD, DWORD, DWORD, DWORD]
    LockFile.restype = WINBOOL
    res = LockFile(hFile, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh)
    return win32_to_errcheck(res, errcheck)


def ReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine, errcheck: bool = True):
    ReadFileEx = kernel32.ReadFileEx
    ReadFileEx.argtypes = [HANDLE, LPVOID, DWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE]
    ReadFileEx.restype = WINBOOL
    res = ReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine)
    return win32_to_errcheck(res, errcheck)


def SetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime, errcheck: bool = True):
    SetFileTime = kernel32.SetFileTime
    SetFileTime.argtypes = [HANDLE, POINTER(FILETIME), POINTER(FILETIME), POINTER(FILETIME)]
    SetFileTime.restype = WINBOOL
    res = SetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime)
    return win32_to_errcheck(res, errcheck)


def UnlockFile(hFile, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh, errcheck: bool = True):
    UnlockFile = kernel32.UnlockFile
    UnlockFile.argtypes = [HANDLE, DWORD, DWORD, DWORD, DWORD]
    UnlockFile.restype = WINBOOL
    res = UnlockFile(hFile, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh)
    return win32_to_errcheck(res, errcheck)


def WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine, errcheck: bool = True):
    WriteFileEx = kernel32.WriteFileEx
    WriteFileEx.argtypes = [HANDLE, LPCVOID, DWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE]
    WriteFileEx.restype = WINBOOL
    res = WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine)
    return win32_to_errcheck(res, errcheck)


def GetFinalPathNameByHandle(hFile, lpszFilePath, cchFilePath, dwFlags, unicode: bool = True):
    GetFinalPathNameByHandle = kernel32.GetFinalPathNameByHandleW if unicode else kernel32.GetFinalPathNameByHandleA
    GetFinalPathNameByHandle.argtypes = [HANDLE, (LPWSTR if unicode else LPSTR), DWORD, DWORD]
    GetFinalPathNameByHandle.restype = DWORD
    res = GetFinalPathNameByHandle(hFile, lpszFilePath, cchFilePath, dwFlags)
    return res


class _WIN32_FILE_ATTRIBUTE_DATA(Structure):
    _fields_ = [
        ('dwFileAttributes', DWORD),
        ('ftCreationTime', FILETIME),
        ('ftLastAccessTime', FILETIME),
        ('ftLastWriteTime', FILETIME),
        ('nFileSizeHigh', DWORD),
        ('nFileSizeLow', DWORD)
    ]

WIN32_FILE_ATTRIBUTE_DATA = _WIN32_FILE_ATTRIBUTE_DATA
LPWIN32_FILE_ATTRIBUTE_DATA = POINTER(WIN32_FILE_ATTRIBUTE_DATA)

class _CREATEFILE2_EXTENDED_PARAMETERS(Structure):
    _fields_ = [
        ('dwSize', DWORD),
        ('dwFileAttributes', DWORD),
        ('dwFileFlags', DWORD),
        ('dwSecurityQosFlags', DWORD),
        ('lpSecurityAttributes', LPSECURITY_ATTRIBUTES),
        ('hTemplateFile', HANDLE)
    ]

CREATEFILE2_EXTENDED_PARAMETERS = _CREATEFILE2_EXTENDED_PARAMETERS
PCREATEFILE2_EXTENDED_PARAMETERS = POINTER(CREATEFILE2_EXTENDED_PARAMETERS)
LPCREATEFILE2_EXTENDED_PARAMETERS = PCREATEFILE2_EXTENDED_PARAMETERS

class DISK_SPACE_INFORMATION(Structure):
    _fields_ = [
        ('ActualTotalAllocationUnits', ULONGLONG),
        ('ActualAvailableAllocationUnits', ULONGLONG),
        ('ActualPoolUnavailableAllocationUnits', ULONGLONG),
        ('CallerTotalAllocationUnits', ULONGLONG),
        ('CallerAvailableAllocationUnits', ULONGLONG),
        ('CallerPoolUnavailableAllocationUnits', ULONGLONG),
        ('UsedAllocationUnits', ULONGLONG),
        ('TotalReservedAllocationUnits', ULONGLONG),
        ('VolumeStorageReserveAllocationUnits', ULONGLONG),
        ('AvailableCommittedAllocationUnits', ULONGLONG),
        ('PoolAvailableAllocationUnits', ULONGLONG),
        ('SectorsPerAllocationUnit', DWORD),
        ('BytesPerSector', DWORD)
    ]


def CreateDirectory(lpPathName, lpSecurityAttributes, unicode: bool = True, errcheck: bool = True):
    CreateDirectory = kernel32.CreateDirectoryW if unicode else kernel32.CreateDirectoryA
    CreateDirectory.argtypes = [(LPCWSTR if unicode else LPCSTR), LPSECURITY_ATTRIBUTES]
    CreateDirectory.restype = WINBOOL
    res = CreateDirectory(lpPathName, lpSecurityAttributes)
    return win32_to_errcheck(res, errcheck)


def DeleteFile(lpFileName, unicode: bool = True, errcheck: bool = True):
    DeleteFile = kernel32.DeleteFileW if unicode else kernel32.DeleteFileA
    DeleteFile.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    DeleteFile.restype = WINBOOL
    res = DeleteFile(lpFileName)
    return win32_to_errcheck(res, errcheck)


def FindClose(hFindFile, errcheck: bool = True):
    FindClose = kernel32.FindClose
    FindClose.argtypes = [HANDLE]
    FindClose.restype = WINBOOL
    res = FindClose(hFindFile)
    return win32_to_errcheck(res, errcheck)


def FindFirstFileEx(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags, unicode: bool = True):
    FindFirstFileEx = kernel32.FindFirstFileExW if unicode else kernel32.FindFirstFileExA
    FindFirstFileEx.argtypes = [(LPCWSTR if unicode else LPCSTR), FINDEX_INFO_LEVELS, LPVOID, UINT, LPVOID, DWORD]
    FindFirstFileEx.restype = HANDLE
    res = FindFirstFileEx(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags)
    return res


def FindNextFile(hFindFile, lpFindFileData, unicode: bool = True, errcheck: bool = True):
    FindNextFile = kernel32.FindNextFileW if unicode else kernel32.FindNextFileA
    FindNextFile.argtypes = [HANDLE, (LPWIN32_FIND_DATAW if unicode else LPWIN32_FIND_DATAA)]
    FindNextFile.restype = WINBOOL
    res = FindNextFile(hFindFile, lpFindFileData)
    return win32_to_errcheck(res, errcheck)


def FlushFileBuffers(hFile, errcheck: bool = True):
    FlushFileBuffers = kernel32.FlushFileBuffers
    FlushFileBuffers.argtypes = [HANDLE]
    FlushFileBuffers.restype = WINBOOL
    res = FlushFileBuffers(hFile)
    return win32_to_errcheck(res, errcheck)


def GetDiskFreeSpaceEx(lpDirectoryName, lpFreeBytesAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes, unicode: bool = True, errcheck: bool = True):
    GetDiskFreeSpaceEx = kernel32.GetDiskFreeSpaceExW if unicode else kernel32.GetDiskFreeSpaceExA
    GetDiskFreeSpaceEx.argtypes = [(LPCWSTR if unicode else LPCSTR), PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER]
    GetDiskFreeSpaceEx.restype = WINBOOL
    res = GetDiskFreeSpaceEx(lpDirectoryName, lpFreeBytesAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes)
    return win32_to_errcheck(res, errcheck)


def GetFileAttributesEx(lpFileName, fInfoLevelId, lpFileInformation, unicode: bool = True, errcheck: bool = True):
    GetFileAttributesEx = kernel32.GetFileAttributesExW if unicode else kernel32.GetFileAttributesExA
    GetFileAttributesEx.argtypes = [(LPCWSTR if unicode else LPCSTR), UINT, LPVOID]
    GetFileAttributesEx.restype = WINBOOL
    res = GetFileAttributesEx(lpFileName, fInfoLevelId, lpFileInformation)
    return win32_to_errcheck(res, errcheck)


def LockFileEx(hFile, dwFlags, dwReserved, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh, lpOverlapped, errcheck: bool = True):
    LockFileEx = kernel32.LockFileEx
    LockFileEx.argtypes = [HANDLE, DWORD, DWORD, DWORD, DWORD, LPOVERLAPPED]
    LockFileEx.restype = WINBOOL
    res = LockFileEx(hFile, dwFlags, dwReserved, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh, lpOverlapped)
    return win32_to_errcheck(res, errcheck)


def ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, errcheck: bool = True):
    ReadFile = kernel32.ReadFile
    ReadFile.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED]
    ReadFile.restype = WINBOOL
    res = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)
    return win32_to_errcheck(res, errcheck)


def RemoveDirectory(lpPathName, unicode: bool = True, errcheck: bool = True):
    RemoveDirectory = kernel32.RemoveDirectoryW if unicode else kernel32.RemoveDirectoryA
    RemoveDirectory.argtypes = [(LPCWSTR if unicode else LPCSTR)]
    RemoveDirectory.restype = WINBOOL
    res = RemoveDirectory(lpPathName)
    return win32_to_errcheck(res, errcheck)


def SetEndOfFile(hFile, errcheck: bool = True):
    SetEndOfFile = kernel32.SetEndOfFile
    SetEndOfFile.argtypes = [HANDLE]
    SetEndOfFile.restype = WINBOOL
    res = SetEndOfFile(hFile)
    return win32_to_errcheck(res, errcheck)


def SetFileAttributes(lpFileName, dwFileAttributes, unicode: bool = True, errcheck: bool = True):
    SetFileAttributes = kernel32.SetFileAttributesW if unicode else kernel32.SetFileAttributesA
    SetFileAttributes.argtypes = [(LPCWSTR if unicode else LPCSTR), DWORD]
    SetFileAttributes.restype = WINBOOL
    res = SetFileAttributes(lpFileName, dwFileAttributes)
    return win32_to_errcheck(res, errcheck)


def SetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod, errcheck: bool = True):
    SetFilePointerEx = kernel32.SetFilePointerEx
    SetFilePointerEx.argtypes = [HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD]
    SetFilePointerEx.restype = WINBOOL
    res = SetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod)
    return win32_to_errcheck(res, errcheck)


def UnlockFileEx(hFile, dwReserved, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh, lpOverlapped, errcheck: bool = True):
    UnlockFileEx = kernel32.UnlockFileEx
    UnlockFileEx.argtypes = [HANDLE, DWORD, DWORD, DWORD, LPOVERLAPPED]
    UnlockFileEx.restype = WINBOOL
    res = UnlockFileEx(hFile, dwReserved, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh, lpOverlapped)
    return win32_to_errcheck(res, errcheck)


def WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped, errcheck: bool = True):
    WriteFile = kernel32.WriteFile
    WriteFile.argtypes = [HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED]
    WriteFile.restype = WINBOOL
    res = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)
    return win32_to_errcheck(res, errcheck)


def GetTempPath(nBufferLength, lpBuffer, unicode: bool = True):
    GetTempPath = kernel32.GetTempPathW if unicode else kernel32.GetTempPathA
    GetTempPath.argtypes = [DWORD, (LPWSTR if unicode else LPSTR)]
    GetTempPath.restype = DWORD
    res = GetTempPath(nBufferLength, lpBuffer)
    return res


def GetDiskSpaceInformation(rootPath, diskSpaceInfo, unicode: bool = True, errcheck: bool = True):
    GetDiskSpaceInformation = kernel32.GetDiskSpaceInformationW if unicode else kernel32.GetDiskSpaceInformationA
    GetDiskSpaceInformation.argtypes = [(LPCWSTR if unicode else LPCSTR), POINTER(DISK_SPACE_INFORMATION)]
    GetDiskSpaceInformation.restype = HRESULT
    res = GetDiskSpaceInformation(rootPath, diskSpaceInfo)
    return hresult_to_errcheck(res, errcheck)


def SetFileInformationByHandle(hFile, FileInformationClass, lpFileInformation, dwBufferSize, errcheck: bool = True):
    SetFileInformationByHandle = kernel32.SetFileInformationByHandle
    SetFileInformationByHandle.argtypes = [HANDLE, UINT, LPVOID, DWORD]
    SetFileInformationByHandle.restype = WINBOOL
    res = SetFileInformationByHandle(hFile, FileInformationClass, lpFileInformation, dwBufferSize)
    return win32_to_errcheck(res, errcheck)


def CreateFile2(lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition, pCreateExParams):
    CreateFile2 = kernel32.CreateFile2
    CreateFile2.argtypes = [LPCWSTR, DWORD, DWORD, DWORD, LPCREATEFILE2_EXTENDED_PARAMETERS]
    CreateFile2.restype = HANDLE
    res = CreateFile2(lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition, pCreateExParams)
    return res


def GetTempPath2(BufferLength, Buffer, unicode: bool = True):
    GetTempPath2 = kernel32.GetTempPath2W if unicode else kernel32.GetTempPath2A
    GetTempPath2.argtypes = [DWORD, (LPWSTR if unicode else LPSTR)]
    GetTempPath2.restype = DWORD
    res = GetTempPath2(BufferLength, Buffer)
    return res
