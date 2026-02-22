# coding = 'utf-8'
# sddi.h

from method.System.winnt import *
from method.System.public_dll import *
from method.System.winusutypes import *
from method.System.errcheck import win32_to_errcheck

SDDL_REVISION_1 = 1
SDDL_REVISION = SDDL_REVISION_1

SDDL_OWNER = "O" if UNICODE else b"O"
SDDL_GROUP = "G" if UNICODE else b"G"
SDDL_DACL = "D" if UNICODE else b"D"
SDDL_SACL = "S" if UNICODE else b"S"

SDDL_PROTECTED = "P" if UNICODE else b"P"
SDDL_AUTO_INHERIT_REQ = "AR" if UNICODE else b"AR"
SDDL_AUTO_INHERITED = "AI" if UNICODE else b"AI"
SDDL_NULL_ACL = "NO_ACCESS_CONTROL" if UNICODE else b"NO_ACCESS_CONTROL"

SDDL_ACCESS_ALLOWED = "A" if UNICODE else b"A"
SDDL_ACCESS_DENIED = "D" if UNICODE else b"D"
SDDL_OBJECT_ACCESS_ALLOWED = "OA" if UNICODE else b"OA"
SDDL_OBJECT_ACCESS_DENIED = "OD" if UNICODE else b"OD"
SDDL_AUDIT = "AU" if UNICODE else b"AU"
SDDL_ALARM = "AL" if UNICODE else b"AL"
SDDL_OBJECT_AUDIT = "OU" if UNICODE else b"OU"
SDDL_OBJECT_ALARM = "OL" if UNICODE else b"OL"
SDDL_MANDATORY_LABEL = "ML" if UNICODE else b"ML"
SDDL_CALLBACK_ACCESS_ALLOWED = "XA" if UNICODE else b"XA"
SDDL_CALLBACK_ACCESS_DENIED = "XD" if UNICODE else b"XD"
SDDL_RESOURCE_ATTRIBUTE = "RA" if UNICODE else b"RA"
SDDL_SCOPED_POLICY_ID = "SP" if UNICODE else b"SP"
SDDL_CALLBACK_AUDIT = "XU" if UNICODE else b"XU"
SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED = "ZA" if UNICODE else b"ZA"

SDDL_CONTAINER_INHERIT = "CI" if UNICODE else b"CI"
SDDL_OBJECT_INHERIT = "OI" if UNICODE else b"OI"
SDDL_NO_PROPAGATE = "NP" if UNICODE else b"NP"
SDDL_INHERIT_ONLY = "IO" if UNICODE else b"IO"
SDDL_INHERITED = "ID" if UNICODE else b"ID"
SDDL_AUDIT_SUCCESS = "SA" if UNICODE else b"SA"
SDDL_AUDIT_FAILURE = "FA" if UNICODE else b"FA"

SDDL_READ_PROPERTY = "RP" if UNICODE else b"RP"
SDDL_WRITE_PROPERTY = "WP" if UNICODE else b"WP"
SDDL_CREATE_CHILD = "CC" if UNICODE else b"CC"
SDDL_DELETE_CHILD = "DC" if UNICODE else b"DC"
SDDL_LIST_CHILDREN = "LC" if UNICODE else b"LC"
SDDL_SELF_WRITE = "SW" if UNICODE else b"SW"
SDDL_LIST_OBJECT = "LO" if UNICODE else b"LO"
SDDL_DELETE_TREE = "DT" if UNICODE else b"DT"
SDDL_CONTROL_ACCESS = "CR" if UNICODE else b"CR"
SDDL_READ_CONTROL = "RC" if UNICODE else b"RC"
SDDL_WRITE_DAC = "WD" if UNICODE else b"WD"
SDDL_WRITE_OWNER = "WO" if UNICODE else b"WO"
SDDL_STANDARD_DELETE = "SD" if UNICODE else b"SD"
SDDL_GENERIC_ALL = "GA" if UNICODE else b"GA"
SDDL_GENERIC_READ = "GR" if UNICODE else b"GR"
SDDL_GENERIC_WRITE = "GW" if UNICODE else b"GW"
SDDL_GENERIC_EXECUTE = "GX" if UNICODE else b"GX"
SDDL_FILE_ALL = "FA" if UNICODE else b"FA"
SDDL_FILE_READ = "FR" if UNICODE else b"FR"
SDDL_FILE_WRITE = "FW" if UNICODE else b"FW"
SDDL_FILE_EXECUTE = "FX" if UNICODE else b"FX"
SDDL_KEY_ALL = "KA" if UNICODE else b"KA"
SDDL_KEY_READ = "KR" if UNICODE else b"KR"
SDDL_KEY_WRITE = "KW" if UNICODE else b"KW"
SDDL_KEY_EXECUTE = "KX" if UNICODE else b"KX"

SDDL_ALIAS_SIZE = 2

SDDL_DOMAIN_ADMINISTRATORS = "DA" if UNICODE else b"DA"
SDDL_DOMAIN_GUESTS = "DG" if UNICODE else b"DG"
SDDL_DOMAIN_USERS = "DU" if UNICODE else b"DU"
SDDL_ENTERPRISE_DOMAIN_CONTROLLERS = "ED" if UNICODE else b"ED"
SDDL_DOMAIN_DOMAIN_CONTROLLERS = "DD" if UNICODE else b"DD"
SDDL_DOMAIN_COMPUTERS = "DC" if UNICODE else b"DC"
SDDL_BUILTIN_ADMINISTRATORS = "BA" if UNICODE else b"BA"
SDDL_BUILTIN_GUESTS = "BG" if UNICODE else b"BG"
SDDL_BUILTIN_USERS = "BU" if UNICODE else b"BU"
SDDL_LOCAL_ADMIN = "LA" if UNICODE else b"LA"
SDDL_LOCAL_GUEST = "LG" if UNICODE else b"LG"
SDDL_ACCOUNT_OPERATORS = "AO" if UNICODE else b"AO"
SDDL_BACKUP_OPERATORS = "BO" if UNICODE else b"BO"
SDDL_PRINTER_OPERATORS = "PO" if UNICODE else b"PO"
SDDL_SERVER_OPERATORS = "SO" if UNICODE else b"SO"
SDDL_AUTHENTICATED_USERS = "AU" if UNICODE else b"AU"
SDDL_PERSONAL_SELF = "PS" if UNICODE else b"PS"
SDDL_CREATOR_OWNER = "CO" if UNICODE else b"CO"
SDDL_CREATOR_GROUP = "CG" if UNICODE else b"CG"
SDDL_LOCAL_SYSTEM = "SY" if UNICODE else b"SY"
SDDL_POWER_USERS = "PU" if UNICODE else b"PU"
SDDL_EVERYONE = "WD" if UNICODE else b"WD"
SDDL_REPLICATOR = "RE" if UNICODE else b"RE"
SDDL_INTERACTIVE = "IU" if UNICODE else b"IU"
SDDL_NETWORK = "NU" if UNICODE else b"NU"
SDDL_SERVICE = "SU" if UNICODE else b"SU"
SDDL_RESTRICTED_CODE = "RC" if UNICODE else b"RC"
SDDL_ANONYMOUS = "AN" if UNICODE else b"AN"
SDDL_SCHEMA_ADMINISTRATORS = "SA" if UNICODE else b"SA"
SDDL_CERT_SERV_ADMINISTRATORS = "CA" if UNICODE else b"CA"
SDDL_RAS_SERVERS = "RS" if UNICODE else b"RS"
SDDL_ENTERPRISE_ADMINS = "EA" if UNICODE else b"EA"
SDDL_GROUP_POLICY_ADMINS = "PA" if UNICODE else b"PA"
SDDL_ALIAS_PREW2KCOMPACC = "RU" if UNICODE else b"RU"
SDDL_LOCAL_SERVICE = "LS" if UNICODE else b"LS"
SDDL_NETWORK_SERVICE = "NS" if UNICODE else b"NS"
SDDL_REMOTE_DESKTOP = "RD" if UNICODE else b"RD"
SDDL_NETWORK_CONFIGURATION_OPS = "NO" if UNICODE else b"NO"
SDDL_PERFMON_USERS = "MU" if UNICODE else b"MU"
SDDL_PERFLOG_USERS = "LU" if UNICODE else b"LU"

SDDL_SEPERATORC = ';' if UNICODE else b';'
SDDL_DELIMINATORC = ':' if UNICODE else b':'
SDDL_ACE_BEGINC = '(' if UNICODE else b'('
SDDL_ACE_ENDC = ')' if UNICODE else b')'

SDDL_SEPERATOR = ";" if UNICODE else b";"
SDDL_DELIMINATOR = ":" if UNICODE else b":"
SDDL_ACE_BEGIN = "(" if UNICODE else b"("
SDDL_ACE_END = ")" if UNICODE else b")"


def ConvertSidToStringSid(Sid, StringSid, unicode: bool = True, errcheck: bool = True) -> None:
    ConvertSidToStringSid = (advapi32.ConvertSidToStringSidW 
                             if unicode else advapi32.ConvertSidToStringSidA
    )
    ConvertSidToStringSid.argtypes = [PSID, POINTER(LPWSTR if unicode else LPSTR)]
    ConvertSidToStringSid.restype = BOOL
    res = ConvertSidToStringSid(Sid, StringSid)
    return win32_to_errcheck(res, errcheck)    


def ConvertStringSidToSid(StringSid, Sid, unicode: bool = True, errcheck: bool = True):
    ConvertStringSidToSid = advapi32.ConvertStringSidToSidW if unicode else advapi32.ConvertStringSidToSidA
    ConvertStringSidToSid.argtypes = [(LPCWSTR if unicode else LPCSTR), PSID]
    ConvertStringSidToSid.restype = WINBOOL
    res = ConvertStringSidToSid(StringSid, Sid)
    return win32_to_errcheck(res, errcheck)


def ConvertStringSecurityDescriptorToSecurityDescriptor(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize, unicode: bool = True, errcheck: bool = True):
    ConvertStringSecurityDescriptorToSecurityDescriptor = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW if unicode else advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorA
    ConvertStringSecurityDescriptorToSecurityDescriptor.argtypes = [(LPCWSTR if unicode else LPCSTR), DWORD, POINTER(PSECURITY_DESCRIPTOR), PULONG]
    ConvertStringSecurityDescriptorToSecurityDescriptor.restype = WINBOOL
    res = ConvertStringSecurityDescriptorToSecurityDescriptor(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize)
    return win32_to_errcheck(res, errcheck)


def ConvertSecurityDescriptorToStringSecurityDescriptor(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen, unicode: bool = True, errcheck: bool = True):
    ConvertSecurityDescriptorToStringSecurityDescriptor = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW if unicode else advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorA
    ConvertSecurityDescriptorToStringSecurityDescriptor.argtypes = [PSECURITY_DESCRIPTOR, DWORD, SECURITY_INFORMATION, POINTER(LPSTR), PULONG]
    ConvertSecurityDescriptorToStringSecurityDescriptor.restype = WINBOOL
    res = ConvertSecurityDescriptorToStringSecurityDescriptor(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen)
    return win32_to_errcheck(res, errcheck)