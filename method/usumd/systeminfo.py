# coding = 'utf-8'

import sys
import platform
from typing import Any
import winreg as _winreg
from struct import calcsize
from method.System.winbase import *
from method.System.sdkddkver import *
from method.System.winusutypes import *
from method.System.shellapi import CloseHandle
from method.System.sddl import ConvertSidToStringSid
from method.System.winnt import TOKEN_QUERY, TokenUser, PTOKEN_USER, PSID
from method.System.processthreadsapi import OpenProcessToken, GetCurrentProcess
from method.System.sysinfoapi import GetSystemFirmwareTable, RSMB, SMBIOS_HEADER


def enum_reg_value(root: int, path: str) -> dict[str, Any]:
    res = {}
    with _winreg.OpenKey(root, path) as key:
        for j in range(_winreg.QueryInfoKey(key)[1]):
            value_name, value_data, *_ = _winreg.EnumValue(key, j)
            res[value_name] = value_data
        return res


class GetUserInfo:
    def __init__(self, SystemName: str | None = None):
        token = HANDLE()
        return_length = DWORD()
        self._SystemName = SystemName
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, byref(token))
        GetTokenInformation(token, TokenUser, 0, 0, byref(return_length), False)
        buffer = (CHAR * return_length.value)()
        GetTokenInformation(token, TokenUser, buffer, return_length, byref(return_length), False)
        token_user = cast(buffer, PTOKEN_USER).contents
        self.user_sid = token_user.User.Sid
        CloseHandle(token, False)

    def _get_username_and_domain(self):
        if not IsValidSid(self.user_sid):
            return None, None

        username_buffer = (WCHAR * 256)()
        domain_buffer = (WCHAR * 256)()
        username_size = DWORD(256)
        domain_size = DWORD(256)
        sid_name_use = DWORD()
        user_sid = self.user_sid
        try:
            LookupAccountSid(
                self._SystemName,
                PSID(user_sid),
                username_buffer,
                byref(username_size),
                domain_buffer,
                byref(domain_size),
                byref(sid_name_use)
            )
        except:
            return None, None

        username = username_buffer.value
        domain = domain_buffer.value
        return domain, username

    @property
    def sid(self) -> (str | None):
        if not IsValidSid(self.user_sid):
            return None
        sid_string_ptr = LPWSTR()
        ConvertSidToStringSid(self.user_sid, byref(sid_string_ptr))
        sid_string = sid_string_ptr.value
        LocalFree(sid_string_ptr)
        return sid_string
    
    @property
    def username(self) -> (str | None):
        return self._get_username_and_domain()[1]

    @property
    def domain(self) -> (str | None):
        return self._get_username_and_domain()[0]


def get_user_info() -> tuple[str | None, str | None, str | None]:
    ''' 
    获取当前用户的信息以及安全标识符 (SID) 

    （即为 whoami /user 的结果）
    '''

    s = GetUserInfo()
    return s.sid, s.domain, s.username


class GetSystemInfo:
    _reg_key = r"Software\Microsoft\Windows NT\CurrentVersion"
    
    def _get_key_value(self, root: int, key_path: str, key: str) -> Any:
        with _winreg.OpenKey(root, key_path) as res:
            value, *_ = _winreg.QueryValueEx(res, key)
            res.Close()
        return value
    
    @property
    def display_version(self) -> (int | None):
        DisplayVersion = 'DisplayVersion'
        if WIN32_WINNT < WIN32_WINNT_WIN8:
            return None
        else:
            return self._get_key_value(_winreg.HKEY_LOCAL_MACHINE, self._reg_key, DisplayVersion)

    @property
    def edition_id(self) -> str:
        EditionID = 'EditionID'
        return self._get_key_value(_winreg.HKEY_LOCAL_MACHINE, self._reg_key, EditionID)
    
    @property
    def current_build(self) -> str:
        CurrentBuild = 'CurrentBuild'
        return self._get_key_value(_winreg.HKEY_LOCAL_MACHINE, self._reg_key, CurrentBuild)
    
    @property
    def major(self) -> int:
        return sys.getwindowsversion().major
    
    @property
    def minor(self) -> int:
        return sys.getwindowsversion().minor
    
    @property
    def micro(self) -> int:
        return int(self.current_build)
    
    @property
    def ubr(self) -> int:
        UBR = 'UBR'
        return self._get_key_value(_winreg.HKEY_LOCAL_MACHINE, self._reg_key, UBR)
    
    @property
    def nt_version(self) -> str:
        return f'{self.major}.{self.minor}'
    
    @property
    def os_name(self) -> str:   # 该 os_name 不是返回 os.name 的值
        return platform.system()
    
    @property
    def os_version(self) -> str:
        return platform.release()
    
    @property
    def os_build(self) -> str:
        return platform.version()
    
    @property
    def os_bits(self) -> int:
        return calcsize('P') * 8
    
    @property
    def os_machine(self) -> str:
        return platform.machine().lower()
    
    @property
    def os_sp_version(self) -> str:
        return platform._win32_ver(version='', csd='', ptype='')[1]

    @property
    def uuid(self) -> (str | None):
        smbiosSize = GetSystemFirmwareTable(RSMB, NULL, NULL, NULL, errcheck=False)
        pSmbios = (UBYTE * smbiosSize)()

        if GetSystemFirmwareTable(RSMB, NULL, smbiosSize, pSmbios, errcheck=False) != smbiosSize:
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
        return f"{data1}-{data2}-{data3}-{data4[0:2].hex()}-{data4[2:].hex()}".upper()



