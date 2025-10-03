# coding = 'utf-8'

''' The sys_win was used Windows API to make. '''

import os
import sys
import winreg
import platform
import subprocess
from .windows import *
from win32com.client import GetObject

wmi = GetObject('winmgmts:')
Win32_Process = wmi.ExecQuery("SELECT * FROM Win32_Process")
Win32_Service = wmi.ExecQuery("SELECT * FROM Win32_Service")
Win32_ComputerSystemProduct = wmi.ExecQuery('SELECT * FROM Win32_ComputerSystemProduct')


def get_self_directory(temp_dir: bool = False) -> str:
    '''Get the path of the file.（获取文件自身路径）'''

    return os.path.dirname(os.path.abspath(
        __file__ if temp_dir else sys.argv[0]))


def enum_reg_value(root: int, path: str) -> dict:
    res = {}
    with winreg.OpenKey(root, path) as key:
        for j in range(winreg.QueryInfoKey(key)[1]):
            value_name, value_data, *_ = winreg.EnumValue(key, j)
            res[value_name] = value_data
        return res


def get_device_UUID() -> (str | None):
    '''Get UUID of the device.（获取设备的UUID）'''

    try:
        for res in Win32_ComputerSystemProduct:
            uuid = res.uuid
        return uuid
    except:
        smbiosSize = GetSystemFirmwareTable('RSMB', NULL, NULL, NULL)
        pSmbios = (UBYTE * smbiosSize)()

        if GetSystemFirmwareTable('RSMB', NULL, smbiosSize, pSmbios) != smbiosSize:
            return None
        
        smbios_data = bytes(pSmbios)
        offset = 8

        while offset < len(smbios_data):
            header = SMBIOS_HEADER.from_buffer_copy(smbios_data, offset)

            # 检查结束标记
            if header.Type == 127 and header.Length == 4:
                return None

            if header.Type == 1 and header.Length >= 0x19:
                uuid_start = offset + 0x08
                if uuid_start + 16 > len(smbios_data):
                    return None

                uuid_bytes = smbios_data[uuid_start:uuid_start + 16]

                if not all(b == 0 for b in uuid_bytes):
                    break

            offset += header.Length

            while offset + 1 < len(smbios_data):
                if smbios_data[offset] == 0 and smbios_data[offset + 1] == 0:
                    offset += 2  # 跳过双空终止符
                    break
                offset += 1

        data1 = uuid_bytes[0:4][::-1]
        data2 = uuid_bytes[4:6][::-1]
        data3 = uuid_bytes[6:8][::-1]
        data4 = uuid_bytes[8:16]
        uuid_bytes = data1 + data2 + data3 + data4

        data1 = uuid_bytes[0:4].hex().upper()
        data2 = uuid_bytes[4:6].hex().upper()
        data3 = uuid_bytes[6:8].hex().upper()
        data4 = uuid_bytes[8:16]
        return f"{data1}-{data2}-{data3}-{data4[0:2].hex().upper()}-{data4[2:].hex().upper()}"


def system_type(sys_basictypes: bool = False, uuid: bool = False) -> dict[str, (str | None)]:
    '''Get information of the system.（获取系统信息）'''

    from struct import calcsize

    reg_key = r"Software\Microsoft\Windows NT\CurrentVersion"
    DisplayVersion = 'DisplayVersion'
    EditionID = 'EditionID'
    CurrentBuild = 'CurrentBuild'
    UBR = 'UBR'

    def _uuid(uuid):
        if uuid:
            try:
                uuid = get_device_UUID()
                if uuid is None:
                    # This is not uuid of WMI.
                    uuid = enum_reg_value(winreg.HKEY_LOCAL_MACHINE, 
                                        r'SOFTWARE\Microsoft\Cryptography')['MachineGuid']
            except:
                try:
                    uuid = enum_reg_value(winreg.HKEY_LOCAL_MACHINE, 
                                        r'SOFTWARE\Microsoft\Cryptography')['MachineGuid']
                except:
                    uuid = None
            result['UUID'] = uuid

    for key in [EditionID, DisplayVersion, CurrentBuild, UBR]:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_key) as result:
                value, *_ = winreg.QueryValueEx(result, key)
        except:
            pass
   
        if key == DisplayVersion:
            if WIN32_WINNT < WIN32_WINNT_WIN8:
                DisplayVersion = None
            else:
                DisplayVersion = value
        elif key == EditionID:
            EditionID = value
        elif key == CurrentBuild:
            CurrentBuild = value
        elif key == UBR:
            UBR = value
    
    result = {}
    major = sys.getwindowsversion().major
    minor = sys.getwindowsversion().minor
    NT_ver = f'{major}.{minor}'
    OS_type = platform.system()
    OS_ver = platform.release()
    OS_build = platform.version()
    OS_bits = calcsize('P') * 8
    OS_machine = platform.machine().lower()
    OS_sp_ver = platform._win32_ver(version='', csd='', ptype='')[1]

    result['OS_type'] = OS_type
    result['OS_ver'] = OS_ver
    result['EditionID'] = EditionID
    result['DisplayVersion'] = DisplayVersion
    result['OS_machine'] = OS_machine
    result['OS_bits'] = str(OS_bits)

    if sys_basictypes: 
        _uuid(uuid=uuid)
        return result

    result['OS_build'] = OS_build
    result['OS_sp_ver'] = OS_sp_ver
    result['NT_ver'] = NT_ver
    result['NT_major'] = str(major)
    result['NT_minor'] = str(minor)
    result['CurrentBuild'] = CurrentBuild
    result['UBR'] = str(UBR)
    _uuid(uuid=uuid)
    return result


def wmi_query_serv() -> tuple[list, list, list, list, list]:
    '''Call wmi to query the service.（调用wmi来查询服务）'''

    exitcode = []
    name = []
    pid = []
    startmode = []
    state = []
    for service in Win32_Service:
        exitcode.append(service.ExitCode)
        name.append(service.Name)    
        pid.append(service.ProcessId) 
        startmode.append(service.StartMode)
        state.append(service.State)
    return exitcode, name, pid, startmode, state


def wmi_query_proc() -> tuple[list, list, list, list, list, list, list]:
    '''Call wmi to query the process.（调用wmi来查询进程）'''

    name = []
    pid = []
    path = []
    description = []
    parent_pid = []
    threadcount = []
    handles = []
    for proc in Win32_Process:
        name.append(proc.Name)
        pid.append(proc.ProcessID)
        path.append(proc.ExecutablePath)
        description.append(proc.Description)
        parent_pid.append(proc.ParentProcessId)
        threadcount.append(proc.ThreadCount)
        handles.append(proc.HandleCount)
    
    num = 0
    for p in path:
        if '\\\\?\\' in str(p):
            path[num] = p[4:]
        num += 1
    return name, pid, path, description, parent_pid, threadcount, handles


def get_proc_path(proc_name: str) -> (str | None):
    '''
    Get the file location from a running program.
    （通过已运行的程序来获取文件位置）
    '''

    name, pid, path, *_ = wmi_query_proc()
    num = 0
    for proc in name:
        if proc_name.lower() == str(proc).lower():
            return path[num]
        num += 1
    return None


def get_serv_or_proc_path(pid: int,
                          dwDesiredAccess: int = PROCESS_QUERY_LIMITED_INFORMATION, 
                          bInheritHandle: bool = False, 
                          dwFlags: int = NULL, 
                          lpExeName: int = MAX_PATH,
                          unicode: bool = True) -> (str | bytes | None):
    
    '''
    Get the location of the file by using the process ID of the running program or service.
    （通过已运行的程序或服务的进程ID来获取文件位置）
    '''
    path = ((WCHAR if unicode else CHAR) * lpExeName)()
    lpdwSize = DWORD(sizeof(path))

    try:
        handle = OpenProcess(dwDesiredAccess=dwDesiredAccess, 
                            bInheritHandle=bInheritHandle, 
                            dwProcessId=pid
        )

        QueryFullProcessImageName(handle, dwFlags, byref(path), byref(lpdwSize), unicode)
        CloseHandle(handle)
        return path.value
    except:
        return None


def open_file_location(path: str) -> None:
    """
    Open the location in Explorer through the file path and select the file.
    （通过文件路径在文件资源管理器中打开文件所在位置并选中文件）
    """
    
    path = os.path.normpath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f'No such file or directory: "{path}"')
    
    ShellExecute(lpFile='explorer.exe', 
                 lpParameters=f'/select, {path}'
    )


def open_file_location2(path: str, dwFlags: int = NULL) -> None:
    """
    Open the location in Explorer through the file path and select the file.
    （通过文件路径在文件资源管理器中打开文件所在位置并选中文件）
    """
    
    if path.startswith('.') or path.startswith('..'):
        path = os.path.abspath(path)

    path = os.path.normpath(path)

    if path == '.':
        path = os.path.abspath(path)
        
    if not os.path.exists(path):
        raise FileNotFoundError(f'No such file or directory: "{path}"')
    
    pidl = ILCreateFromPath(path)
    CoInitialize()
    SHOpenFolderAndSelectItems(pidl, NULL, NULL, dwFlags=dwFlags)
    CoUninitialize()
    ILFree(pidl)


def RunAsAdmin(hwnd: int = HWND(), 
               fMask: int = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE, 
               lpVerb: str = 'runas', 
               lpFile: str = sys.executable, 
               lpParameters: str = os.path.normpath(subprocess.list2cmdline(sys.argv)), 
               nShow: int = SW_NORMAL) -> None:
    
    '''
    Use administrator's permission to run.（以管理员权限运行）

    e.g. :
    =====

    >>> import subprocess
    >>> from method import RunAsAdmin
    >>> RunAsAdmin()
    >>> subprocess.run(['cmd.exe'], shell=True, check=True)
    '''

    if IsUserAnAdmin():
        return
    
    try:
        handle = ShellExecuteEx(hwnd=hwnd, 
                                fMask=fMask, 
                                lpVerb=lpVerb, 
                                lpFile=lpFile, 
                                lpParameters=lpParameters, 
                                nShow=nShow
        )
        CloseHandle(handle)
    except: 
        pass

    sys.exit(0)


def RunAsAdmin2(hwnd: int = HWND(),
                lpOperation: str = 'runas', 
                lpFile: str = sys.executable, 
                lpParameters=f'{os.path.abspath(sys.argv[0])} --admin',
                nShowCmd: int = SW_NORMAL) -> None:
    
    '''
    Use administrator's permission to run.（以管理员权限运行）

    e.g. :
    =====

    >>> import subprocess
    >>> from method import RunAsAdmin2
    >>> RunAsAdmin2()
    >>> subprocess.run(['cmd.exe'], shell=True, check=True)
    '''
    
    if IsUserAnAdmin():
        return
    
    if '--admin' not in sys.argv:
        try:
            ShellExecute(lpOperation=lpOperation,
                        lpFile=lpFile,
                        lpParameters=lpParameters,
                        hwnd=hwnd,
                        nShowCmd=nShowCmd
            )
        except:
            pass

    sys.exit(0)


SYSTEMROOT: str = os.environ['SYSTEMROOT']
APPDATA: str = os.environ['APPDATA']
HOMEDRIVE: str = os.environ['HOMEDRIVE']
HOMEPATH: str = os.environ['HOMEPATH']
LOCALAPPDATA: str = os.environ['LOCALAPPDATA']
LOGONSERVER: str = os.environ['LOGONSERVER']
USERDOMAIN: str = os.environ['USERDOMAIN']
USERDOMAIN_ROAMINGPROFILE: str = os.environ['USERDOMAIN_ROAMINGPROFILE']
USERNAME: str = os.environ['USERNAME']
USERPROFILE: str = os.environ['USERPROFILE']
HOME: str = HOMEDRIVE + HOMEPATH
TEMP: str = os.environ['TEMP']
TMP: str = os.environ['TMP']
WBEM: str = f'{SYSTEMROOT}\\{'System32' if sys.maxsize > 2 ** 32 else ('SysWOW64' if sys.maxsize < 2 ** 32 else 'System32')}\\wbem'     # WMI path


def _get_folder(csidl: int) -> str:
    path = ((WCHAR if UNICODE else CHAR) * MAX_PATH)()
    SHGetFolderPath(NULL, csidl | CSIDL_FLAG_NO_ALIAS, NULL, SHGFP_TYPE_CURRENT, path, UNICODE)
    if UNICODE:
        return path.value
    return path.value.decode('utf-8')


##############################################################################
def Desktop(common: bool = False) -> str:
    return _get_folder(CSIDL_COMMON_DESKTOPDIRECTORY if common else CSIDL_DESKTOP)


def Roaming() -> str:
    return _get_folder(CSIDL_APPDATA)


def INetCache() -> str:
    return _get_folder(CSIDL_INTERNET_CACHE)


def INetCookies() -> str:
    return _get_folder(CSIDL_COOKIES)


def Favorites() -> str:
    return _get_folder(CSIDL_FAVORITES)


def History() -> str:
    return _get_folder(CSIDL_HISTORY)


def Local() -> str:
    return _get_folder(CSIDL_LOCAL_APPDATA)


def Music(common: bool = False) -> str:
    return _get_folder(CSIDL_COMMON_MUSIC if common else CSIDL_MYMUSIC)


def Pictures(common: bool = False) -> str:
    return _get_folder(CSIDL_COMMON_PICTURES if common else CSIDL_MYPICTURES)


def Videos(common: bool = False) -> str:
    return _get_folder(CSIDL_COMMON_VIDEO if common else CSIDL_MYVIDEO)


def Network_Shortcuts() -> str:
    return _get_folder(CSIDL_NETHOOD)


def Documents(common: bool = False) -> str:
    return _get_folder(CSIDL_COMMON_DOCUMENTS if common else CSIDL_MYDOCUMENTS)


def Printer_Shortcuts() -> str:
    return _get_folder(CSIDL_PRINTHOOD)


def Programs(common: bool = False) -> str:
    return _get_folder(CSIDL_COMMON_PROGRAMS if common else CSIDL_PROGRAMS)


def Recent() -> str:
    return _get_folder(CSIDL_RECENT)


def SendTo() -> str:
    return _get_folder(CSIDL_SENDTO)


def Start_Menu(common: bool = False) -> str:
    return _get_folder(CSIDL_STARTMENU if common else CSIDL_COMMON_STARTMENU)


def Startup(common: bool = False) -> str:
    return _get_folder(CSIDL_COMMON_STARTUP if common else CSIDL_ALTSTARTUP)


def Templates(common: bool = False) -> str:
    return _get_folder(CSIDL_COMMON_TEMPLATES if common else CSIDL_TEMPLATES)


def Downloads() -> str: 
    path = c_wchar_p()
    SHGetKnownFolderPath(FOLDERID_Downloads, NULL, NULL, byref(path))
    return path.value


def Administrative_Tools(common: bool = False) -> str:
    return _get_folder(CSIDL_COMMON_ADMINTOOLS if common else CSIDL_ADMINTOOLS)


def ProgramData() -> str:
    return _get_folder(CSIDL_COMMON_APPDATA)


def Links() -> str:
    path = c_wchar_p()
    SHGetKnownFolderPath(FOLDERID_Links, NULL, NULL, byref(path))
    return path.value


def Program_Files(X86: bool = False):
    return _get_folder(CSIDL_PROGRAM_FILESX86 if X86 and WIN64 else CSIDL_PROGRAM_FILES)


def Common_Files(X86: bool = False):
    return _get_folder(CSIDL_PROGRAM_FILES_COMMONX86 if X86 and WIN64 else CSIDL_PROGRAM_FILES_COMMON)
