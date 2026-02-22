# coding = 'utf-8'
# securitybaseapi.h

from typing import Any
from method.System.minwinbase import *
from method.System.errcheck import win32_to_errcheck, hresult_to_errcheck

PSID = PVOID


def AccessCheck(pSecurityDescriptor, ClientToken, DesiredAccess, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus, errcheck: bool = True):
    AccessCheck = advapi32.AccessCheck
    AccessCheck.argtypes = [PSECURITY_DESCRIPTOR, HANDLE, DWORD, PGENERIC_MAPPING, PPRIVILEGE_SET, LPDWORD, LPDWORD, LPBOOL]
    AccessCheck.restype = WINBOOL
    res = AccessCheck(pSecurityDescriptor, ClientToken, DesiredAccess, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus)
    return win32_to_errcheck(res, errcheck)


def AccessCheckAndAuditAlarm(SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, DesiredAccess, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, pfGenerateOnClose, unicode: bool = True, errcheck: bool = True):
    AccessCheckAndAuditAlarm = advapi32.AccessCheckAndAuditAlarmW if unicode else advapi32.AccessCheckAndAuditAlarmA
    AccessCheckAndAuditAlarm.argtypes = [(LPCWSTR if unicode else LPSTR), LPVOID, (LPWSTR if unicode else LPSTR), (LPWSTR if unicode else LPSTR), PSECURITY_DESCRIPTOR, DWORD, PGENERIC_MAPPING, WINBOOL, LPDWORD, LPBOOL, LPBOOL]
    AccessCheckAndAuditAlarm.restype = WINBOOL
    res = AccessCheckAndAuditAlarm(SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, DesiredAccess, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, pfGenerateOnClose)
    return win32_to_errcheck(res, errcheck)


def AccessCheckByType(pSecurityDescriptor, PrincipalSelfSid, ClientToken, DesiredAccess, ObjectTypeList, ObjectTypeListLength, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus, errcheck: bool = True):
    AccessCheckByType = advapi32.AccessCheckByType
    AccessCheckByType.argtypes = [PSECURITY_DESCRIPTOR, PSID, HANDLE, DWORD, POBJECT_TYPE_LIST, DWORD, PGENERIC_MAPPING, PPRIVILEGE_SET, LPDWORD, LPDWORD, LPBOOL]
    AccessCheckByType.restype = WINBOOL
    res = AccessCheckByType(pSecurityDescriptor, PrincipalSelfSid, ClientToken, DesiredAccess, ObjectTypeList, ObjectTypeListLength, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus)
    return win32_to_errcheck(res, errcheck)


def AccessCheckByTypeResultList(pSecurityDescriptor, PrincipalSelfSid, ClientToken, DesiredAccess, ObjectTypeList, ObjectTypeListLength, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccessList, AccessStatusList, errcheck: bool = True):
    AccessCheckByTypeResultList = advapi32.AccessCheckByTypeResultList
    AccessCheckByTypeResultList.argtypes = [PSECURITY_DESCRIPTOR, PSID, HANDLE, DWORD, POBJECT_TYPE_LIST, DWORD, PGENERIC_MAPPING, PPRIVILEGE_SET, LPDWORD, LPDWORD, LPDWORD]   
    AccessCheckByTypeResultList.restype = WINBOOL
    res = AccessCheckByTypeResultList(pSecurityDescriptor, PrincipalSelfSid, ClientToken, DesiredAccess, ObjectTypeList, ObjectTypeListLength, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccessList, AccessStatusList)
    return win32_to_errcheck(res, errcheck)


def AccessCheckByTypeAndAuditAlarm(SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, pfGenerateOnClose, unicode: bool = True, errcheck: bool = True):
    AccessCheckByTypeAndAuditAlarm = advapi32.AccessCheckByTypeAndAuditAlarmW if unicode else advapi32.AccessCheckByTypeAndAuditAlarmA
    AccessCheckByTypeAndAuditAlarm.argtypes = [(LPCWSTR if unicode else LPSTR), LPVOID, (LPCWSTR if unicode else LPSTR), (LPCWSTR if unicode else LPSTR), PSECURITY_DESCRIPTOR, PSID, DWORD, AUDIT_EVENT_TYPE, DWORD, POBJECT_TYPE_LIST, DWORD, PGENERIC_MAPPING, WINBOOL, LPDWORD, LPBOOL, LPBOOL]
    AccessCheckByTypeAndAuditAlarm.restype = WINBOOL
    res = AccessCheckByTypeAndAuditAlarm(SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, pfGenerateOnClose)
    return win32_to_errcheck(res, errcheck)


def AccessCheckByTypeResultListAndAuditAlarm(SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccessList, AccessStatusList, pfGenerateOnClose, unicode: bool = True, errcheck: bool = True):
    AccessCheckByTypeResultListAndAuditAlarm = advapi32.AccessCheckByTypeResultListAndAuditAlarmW if unicode else advapi32.AccessCheckByTypeResultListAndAuditAlarmA
    AccessCheckByTypeResultListAndAuditAlarm.argtypes = [(LPCWSTR if unicode else LPSTR), LPVOID, (LPCWSTR if unicode else LPSTR), (LPCWSTR if unicode else LPSTR), PSECURITY_DESCRIPTOR, PSID, DWORD, AUDIT_EVENT_TYPE, DWORD, POBJECT_TYPE_LIST, DWORD, PGENERIC_MAPPING, WINBOOL, LPDWORD, LPDWORD, LPBOOL]
    AccessCheckByTypeResultListAndAuditAlarm.restype = WINBOOL
    res = AccessCheckByTypeResultListAndAuditAlarm(SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccessList, AccessStatusList, pfGenerateOnClose)
    return win32_to_errcheck(res, errcheck)


def AccessCheckByTypeResultListAndAuditAlarmByHandle(SubsystemName, HandleId, ClientToken, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccessList, AccessStatusList, pfGenerateOnClose, unicode: bool = True, errcheck: bool = True):
    AccessCheckByTypeResultListAndAuditAlarmByHandle = advapi32.AccessCheckByTypeResultListAndAuditAlarmByHandleW if unicode else advapi32.AccessCheckByTypeResultListAndAuditAlarmByHandleA
    AccessCheckByTypeResultListAndAuditAlarmByHandle.argtypes = [(LPCWSTR if unicode else LPSTR), LPVOID, HANDLE, (LPCWSTR if unicode else LPSTR), (LPCWSTR if unicode else LPSTR), PSECURITY_DESCRIPTOR, PSID, DWORD, AUDIT_EVENT_TYPE, DWORD, POBJECT_TYPE_LIST, DWORD, PGENERIC_MAPPING, WINBOOL, LPDWORD, LPDWORD, LPBOOL]
    AccessCheckByTypeResultListAndAuditAlarmByHandle.restype = WINBOOL
    res = AccessCheckByTypeResultListAndAuditAlarmByHandle(SubsystemName, HandleId, ClientToken, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccessList, AccessStatusList, pfGenerateOnClose)
    return win32_to_errcheck(res, errcheck)


def AddAccessAllowedObjectAce(pAcl, dwAceRevision, AceFlags, AccessMask, ObjectTypeGuid, InheritedObjectTypeGuid, pSid, errcheck: bool = True):
    AddAccessAllowedObjectAce = advapi32.AddAccessAllowedObjectAce
    AddAccessAllowedObjectAce.argtypes = [PACL, DWORD, DWORD, DWORD, POINTER(GUID), POINTER(GUID), PSID]
    AddAccessAllowedObjectAce.restype = WINBOOL
    res = AddAccessAllowedObjectAce(pAcl, dwAceRevision, AceFlags, AccessMask, ObjectTypeGuid, InheritedObjectTypeGuid, pSid)
    return win32_to_errcheck(res, errcheck)


def AddAccessDeniedAce(pAcl, dwAceRevision, AccessMask, pSid, errcheck: bool = True):
    AddAccessDeniedAce = advapi32.AddAccessDeniedAce
    AddAccessDeniedAce.argtypes = [PACL, DWORD, DWORD, PSID]
    AddAccessDeniedAce.restype = WINBOOL
    res = AddAccessDeniedAce(pAcl, dwAceRevision, AccessMask, pSid)
    return win32_to_errcheck(res, errcheck)


def AddAccessDeniedAceEx(pAcl, dwAceRevision, AceFlags, AccessMask, pSid, errcheck: bool = True):
    AddAccessDeniedAceEx = advapi32.AddAccessDeniedAceEx
    AddAccessDeniedAceEx.argtypes = [PACL, DWORD, DWORD, DWORD, PSID]
    AddAccessDeniedAceEx.restype = WINBOOL
    res = AddAccessDeniedAceEx(pAcl, dwAceRevision, AceFlags, AccessMask, pSid)
    return win32_to_errcheck(res, errcheck)


def AddAccessDeniedObjectAce(pAcl, dwAceRevision, AceFlags, AccessMask, ObjectTypeGuid, InheritedObjectTypeGuid, pSid, errcheck: bool = True):
    AddAccessDeniedObjectAce = advapi32.AddAccessDeniedObjectAce
    AddAccessDeniedObjectAce.argtypes = [PACL, DWORD, DWORD, DWORD, POINTER(GUID), POINTER(GUID), PSID]
    AddAccessDeniedObjectAce.restype = WINBOOL
    res = AddAccessDeniedObjectAce(pAcl, dwAceRevision, AceFlags, AccessMask, ObjectTypeGuid, InheritedObjectTypeGuid, pSid)
    return win32_to_errcheck(res, errcheck)


def AddAuditAccessAce(pAcl, dwAceRevision, dwAccessMask, pSid, bAuditSuccess, bAuditFailure, errcheck: bool = True):
    AddAuditAccessAce = advapi32.AddAuditAccessAce
    AddAuditAccessAce.argtypes = [PACL, DWORD, DWORD, PSID, WINBOOL, WINBOOL]
    AddAuditAccessAce.restype = WINBOOL
    res = AddAuditAccessAce(pAcl, dwAceRevision, dwAccessMask, pSid, bAuditSuccess, bAuditFailure)
    return win32_to_errcheck(res, errcheck)


def AddAuditAccessAceEx(pAcl, dwAceRevision, AceFlags, dwAccessMask, pSid, bAuditSuccess, bAuditFailure, errcheck: bool = True):
    AddAuditAccessAceEx = advapi32.AddAuditAccessAceEx
    AddAuditAccessAceEx.argtypes = [PACL, DWORD, DWORD, DWORD, PSID, WINBOOL, WINBOOL]
    AddAuditAccessAceEx.restype = WINBOOL
    res = AddAuditAccessAceEx(pAcl, dwAceRevision, AceFlags, dwAccessMask, pSid, bAuditSuccess, bAuditFailure)
    return win32_to_errcheck(res, errcheck)


def AddAuditAccessObjectAce(pAcl, dwAceRevision, AceFlags, AccessMask, ObjectTypeGuid, InheritedObjectTypeGuid, pSid, bAuditSuccess, bAuditFailure, errcheck: bool = True):     
    AddAuditAccessObjectAce = advapi32.AddAuditAccessObjectAce
    AddAuditAccessObjectAce.argtypes = [PACL, DWORD, DWORD, DWORD, POINTER(GUID), POINTER(GUID), PSID, WINBOOL, WINBOOL]
    AddAuditAccessObjectAce.restype = WINBOOL
    res = AddAuditAccessObjectAce(pAcl, dwAceRevision, AceFlags, AccessMask, ObjectTypeGuid, InheritedObjectTypeGuid, pSid, bAuditSuccess, bAuditFailure)
    return win32_to_errcheck(res, errcheck)


def AddResourceAttributeAce(pAcl, dwAceRevision, AceFlags, AccessMask, pSid, pAttributeInfo, pReturnLength, errcheck: bool = True):
    AddResourceAttributeAce = advapi32.AddResourceAttributeAce
    AddResourceAttributeAce.argtypes = [PACL, DWORD, DWORD, DWORD, PSID, PCLAIM_SECURITY_ATTRIBUTES_INFORMATION, PDWORD]
    AddResourceAttributeAce.restype = WINBOOL
    res = AddResourceAttributeAce(pAcl, dwAceRevision, AceFlags, AccessMask, pSid, pAttributeInfo, pReturnLength)
    return win32_to_errcheck(res, errcheck)


def AddScopedPolicyIDAce(pAcl, dwAceRevision, AceFlags, AccessMask, pSid, errcheck: bool = True):
    AddScopedPolicyIDAce = advapi32.AddScopedPolicyIDAce
    AddScopedPolicyIDAce.argtypes = [PACL, DWORD, DWORD, DWORD, PSID]
    AddScopedPolicyIDAce.restype = WINBOOL
    res = AddScopedPolicyIDAce(pAcl, dwAceRevision, AceFlags, AccessMask, pSid)
    return win32_to_errcheck(res, errcheck)


def AreAllAccessesGranted(GrantedAccess, DesiredAccess, errcheck: bool = True):
    AreAllAccessesGranted = advapi32.AreAllAccessesGranted
    AreAllAccessesGranted.argtypes = [DWORD, DWORD]
    AreAllAccessesGranted.restype = WINBOOL
    res = AreAllAccessesGranted(GrantedAccess, DesiredAccess)
    return win32_to_errcheck(res, errcheck)


def AreAnyAccessesGranted(GrantedAccess, DesiredAccess, errcheck: bool = True):
    AreAnyAccessesGranted = advapi32.AreAnyAccessesGranted
    AreAnyAccessesGranted.argtypes = [DWORD, DWORD]
    AreAnyAccessesGranted.restype = WINBOOL
    res = AreAnyAccessesGranted(GrantedAccess, DesiredAccess)
    return win32_to_errcheck(res, errcheck)


def CheckTokenCapability(TokenHandle, CapabilitySidToCheck, HasCapability, errcheck: bool = True):
    CheckTokenCapability = advapi32.CheckTokenCapability
    CheckTokenCapability.argtypes = [HANDLE, PSID, PBOOL]
    CheckTokenCapability.restype = WINBOOL
    res = CheckTokenCapability(TokenHandle, CapabilitySidToCheck, HasCapability)
    return win32_to_errcheck(res, errcheck)


def GetAppContainerAce(Acl, StartingAceIndex, AppContainerAce, AppContainerAceIndex, errcheck: bool = True):
    GetAppContainerAce = advapi32.GetAppContainerAce
    GetAppContainerAce.argtypes = [PACL, DWORD, POINTER(PVOID), POINTER(DWORD)]
    GetAppContainerAce.restype = WINBOOL
    res = GetAppContainerAce(Acl, StartingAceIndex, AppContainerAce, AppContainerAceIndex)
    return win32_to_errcheck(res, errcheck)


def ConvertToAutoInheritPrivateObjectSecurity(ParentDescriptor, CurrentSecurityDescriptor, NewSecurityDescriptor, ObjectType, IsDirectoryObject, GenericMapping, errcheck: bool = True):
    ConvertToAutoInheritPrivateObjectSecurity = advapi32.ConvertToAutoInheritPrivateObjectSecurity
    ConvertToAutoInheritPrivateObjectSecurity.argtypes = [PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, POINTER(PSECURITY_DESCRIPTOR), POINTER(GUID), BOOLEAN, PGENERIC_MAPPING]  
    ConvertToAutoInheritPrivateObjectSecurity.restype = WINBOOL
    res = ConvertToAutoInheritPrivateObjectSecurity(ParentDescriptor, CurrentSecurityDescriptor, NewSecurityDescriptor, ObjectType, IsDirectoryObject, GenericMapping)
    return win32_to_errcheck(res, errcheck)


def CreatePrivateObjectSecurity(ParentDescriptor, CreatorDescriptor, NewDescriptor, IsDirectoryObject, Token, GenericMapping, errcheck: bool = True):
    CreatePrivateObjectSecurity = advapi32.CreatePrivateObjectSecurity
    CreatePrivateObjectSecurity.argtypes = [PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, POINTER(PSECURITY_DESCRIPTOR), WINBOOL, HANDLE, PGENERIC_MAPPING]
    CreatePrivateObjectSecurity.restype = WINBOOL
    res = CreatePrivateObjectSecurity(ParentDescriptor, CreatorDescriptor, NewDescriptor, IsDirectoryObject, Token, GenericMapping)
    return win32_to_errcheck(res, errcheck)


def CreatePrivateObjectSecurityEx(ParentDescriptor, CreatorDescriptor, NewDescriptor, ObjectType, IsContainerObject, AutoInheritFlags, Token, GenericMapping, errcheck: bool = True):
    CreatePrivateObjectSecurityEx = advapi32.CreatePrivateObjectSecurityEx
    CreatePrivateObjectSecurityEx.argtypes = [PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, POINTER(PSECURITY_DESCRIPTOR), POINTER(GUID), WINBOOL, ULONG, HANDLE, PGENERIC_MAPPING]
    CreatePrivateObjectSecurityEx.restype = WINBOOL
    res = CreatePrivateObjectSecurityEx(ParentDescriptor, CreatorDescriptor, NewDescriptor, ObjectType, IsContainerObject, AutoInheritFlags, Token, GenericMapping)
    return win32_to_errcheck(res, errcheck)


def CreatePrivateObjectSecurityWithMultipleInheritance(ParentDescriptor, CreatorDescriptor, NewDescriptor, ObjectTypes, GuidCount, IsContainerObject, AutoInheritFlags, Token, GenericMapping, errcheck: bool = True):
    CreatePrivateObjectSecurityWithMultipleInheritance = advapi32.CreatePrivateObjectSecurityWithMultipleInheritance
    CreatePrivateObjectSecurityWithMultipleInheritance.argtypes = [PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, POINTER(PSECURITY_DESCRIPTOR), POINTER(POINTER(GUID)), ULONG, WINBOOL, ULONG, HANDLE, PGENERIC_MAPPING]
    CreatePrivateObjectSecurityWithMultipleInheritance.restype = WINBOOL
    res = CreatePrivateObjectSecurityWithMultipleInheritance(ParentDescriptor, CreatorDescriptor, NewDescriptor, ObjectTypes, GuidCount, IsContainerObject, AutoInheritFlags, Token, GenericMapping)
    return win32_to_errcheck(res, errcheck)


def CreateRestrictedToken(ExistingTokenHandle, Flags, DisableSidCount, SidsToDisable, DeletePrivilegeCount, PrivilegesToDelete, RestrictedSidCount, SidsToRestrict, NewTokenHandle, errcheck: bool = True):
    CreateRestrictedToken = advapi32.CreateRestrictedToken
    CreateRestrictedToken.argtypes = [HANDLE, DWORD, DWORD, PSID_AND_ATTRIBUTES, DWORD, PLUID_AND_ATTRIBUTES, DWORD, PSID_AND_ATTRIBUTES, PHANDLE]
    CreateRestrictedToken.restype = WINBOOL
    res = CreateRestrictedToken(ExistingTokenHandle, Flags, DisableSidCount, SidsToDisable, DeletePrivilegeCount, PrivilegesToDelete, RestrictedSidCount, SidsToRestrict, NewTokenHandle)
    return win32_to_errcheck(res, errcheck)


def DestroyPrivateObjectSecurity(errcheck: bool = True):
    DestroyPrivateObjectSecurity = advapi32.DestroyPrivateObjectSecurity
    DestroyPrivateObjectSecurity.restype = WINBOOL
    res = DestroyPrivateObjectSecurity()
    return win32_to_errcheck(res, errcheck)


def EqualPrefixSid(pSid1, pSid2, errcheck: bool = True):
    EqualPrefixSid = advapi32.EqualPrefixSid
    EqualPrefixSid.argtypes = [PSID, PSID]
    EqualPrefixSid.restype = WINBOOL
    res = EqualPrefixSid(pSid1, pSid2)
    return win32_to_errcheck(res, errcheck)


def EqualSid(pSid1, pSid2, errcheck: bool = True):
    EqualSid = advapi32.EqualSid
    EqualSid.argtypes = [PSID, PSID]
    EqualSid.restype = WINBOOL
    res = EqualSid(pSid1, pSid2)
    return win32_to_errcheck(res, errcheck)


def FindFirstFreeAce(pAcl, pAce, errcheck: bool = True):
    FindFirstFreeAce = advapi32.FindFirstFreeAce
    FindFirstFreeAce.argtypes = [PACL, POINTER(LPVOID)]
    FindFirstFreeAce.restype = WINBOOL
    res = FindFirstFreeAce(pAcl, pAce)
    return win32_to_errcheck(res, errcheck)


def GetFileSecurity(lpFileName, RequestedInformation, pSecurityDescriptor, nLength, lpnLengthNeeded, unicode: bool = True, errcheck: bool = True):
    GetFileSecurity = advapi32.GetFileSecurityW if unicode else advapi32.GetFileSecurityA
    GetFileSecurity.argtypes = [(LPCWSTR if unicode else LPSTR), SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, LPDWORD]
    GetFileSecurity.restype = WINBOOL
    res = GetFileSecurity(lpFileName, RequestedInformation, pSecurityDescriptor, nLength, lpnLengthNeeded)
    return win32_to_errcheck(res, errcheck)


def GetPrivateObjectSecurity(ObjectDescriptor, SecurityInformation, ResultantDescriptor, DescriptorLength, ReturnLength, errcheck: bool = True):
    GetPrivateObjectSecurity = advapi32.GetPrivateObjectSecurity
    GetPrivateObjectSecurity.argtypes = [PSECURITY_DESCRIPTOR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, PDWORD]
    GetPrivateObjectSecurity.restype = WINBOOL
    res = GetPrivateObjectSecurity(ObjectDescriptor, SecurityInformation, ResultantDescriptor, DescriptorLength, ReturnLength)
    return win32_to_errcheck(res, errcheck)


def ImpersonateAnonymousToken(errcheck: bool = True):
    ImpersonateAnonymousToken = advapi32.ImpersonateAnonymousToken
    ImpersonateAnonymousToken.restype = WINBOOL
    res = ImpersonateAnonymousToken()
    return win32_to_errcheck(res, errcheck)


def ImpersonateLoggedOnUser(errcheck: bool = True):
    ImpersonateLoggedOnUser = advapi32.ImpersonateLoggedOnUser
    ImpersonateLoggedOnUser.restype = WINBOOL
    res = ImpersonateLoggedOnUser()
    return win32_to_errcheck(res, errcheck)


def ImpersonateSelf(errcheck: bool = True):
    ImpersonateSelf = advapi32.ImpersonateSelf
    ImpersonateSelf.restype = WINBOOL
    res = ImpersonateSelf()
    return win32_to_errcheck(res, errcheck)


def IsTokenRestricted():
    IsTokenRestricted = advapi32.IsTokenRestricted
    IsTokenRestricted.restype = WINBOOL
    res = IsTokenRestricted()
    return res


def MapGenericMask(AccessMask, GenericMapping):
    MapGenericMask = advapi32.MapGenericMask
    MapGenericMask.argtypes = [PDWORD, PGENERIC_MAPPING]
    MapGenericMask.restype = VOID
    res = MapGenericMask(AccessMask, GenericMapping)
    return res


def ObjectCloseAuditAlarm(SubsystemName, HandleId, GenerateOnClose, unicode: bool = True, errcheck: bool = True):
    ObjectCloseAuditAlarm = advapi32.ObjectCloseAuditAlarmW if unicode else advapi32.ObjectCloseAuditAlarmA
    ObjectCloseAuditAlarm.argtypes = [(LPCWSTR if unicode else LPSTR), LPVOID, WINBOOL]
    ObjectCloseAuditAlarm.restype = WINBOOL
    res = ObjectCloseAuditAlarm(SubsystemName, HandleId, GenerateOnClose)
    return win32_to_errcheck(res, errcheck)


def ObjectDeleteAuditAlarm(SubsystemName, HandleId, GenerateOnClose, unicode: bool = True, errcheck: bool = True):
    ObjectDeleteAuditAlarm = advapi32.ObjectDeleteAuditAlarmW if unicode else advapi32.ObjectDeleteAuditAlarmA
    ObjectDeleteAuditAlarm.argtypes = [(LPCWSTR if unicode else LPSTR), LPVOID, WINBOOL]
    ObjectDeleteAuditAlarm.restype = WINBOOL
    res = ObjectDeleteAuditAlarm(SubsystemName, HandleId, GenerateOnClose)
    return win32_to_errcheck(res, errcheck)


def ObjectOpenAuditAlarm(SubsystemName, HandleId, ObjectTypeName, ObjectName, pSecurityDescriptor, ClientToken, DesiredAccess, GrantedAccess, Privileges, ObjectCreation, AccessGranted, GenerateOnClose, unicode: bool = True, errcheck: bool = True):
    ObjectOpenAuditAlarm = advapi32.ObjectOpenAuditAlarmW if unicode else advapi32.ObjectOpenAuditAlarmA
    ObjectOpenAuditAlarm.argtypes = [(LPCWSTR if unicode else LPSTR), LPVOID, (LPWSTR if unicode else LPSTR), (LPWSTR if unicode else LPSTR), PSECURITY_DESCRIPTOR, HANDLE, DWORD, DWORD, PPRIVILEGE_SET, WINBOOL, WINBOOL, LPBOOL]
    ObjectOpenAuditAlarm.restype = WINBOOL
    res = ObjectOpenAuditAlarm(SubsystemName, HandleId, ObjectTypeName, ObjectName, pSecurityDescriptor, ClientToken, DesiredAccess, GrantedAccess, Privileges, ObjectCreation, AccessGranted, GenerateOnClose)
    return win32_to_errcheck(res, errcheck)


def ObjectPrivilegeAuditAlarm(SubsystemName, HandleId, ClientToken, DesiredAccess, Privileges, AccessGranted, unicode: bool = True, errcheck: bool = True):
    ObjectPrivilegeAuditAlarm = advapi32.ObjectPrivilegeAuditAlarmW if unicode else advapi32.ObjectPrivilegeAuditAlarmA
    ObjectPrivilegeAuditAlarm.argtypes = [(LPCWSTR if unicode else LPSTR), LPVOID, HANDLE, DWORD, PPRIVILEGE_SET, WINBOOL]
    ObjectPrivilegeAuditAlarm.restype = WINBOOL
    res = ObjectPrivilegeAuditAlarm(SubsystemName, HandleId, ClientToken, DesiredAccess, Privileges, AccessGranted)
    return win32_to_errcheck(res, errcheck)


def PrivilegeCheck(ClientToken, RequiredPrivileges, pfResult, errcheck: bool = True):
    PrivilegeCheck = advapi32.PrivilegeCheck
    PrivilegeCheck.argtypes = [HANDLE, PPRIVILEGE_SET, LPBOOL]
    PrivilegeCheck.restype = WINBOOL
    res = PrivilegeCheck(ClientToken, RequiredPrivileges, pfResult)
    return win32_to_errcheck(res, errcheck)


def PrivilegedServiceAuditAlarm(SubsystemName, ServiceName, ClientToken, Privileges, AccessGranted, unicode: bool = True, errcheck: bool = True):
    PrivilegedServiceAuditAlarm = advapi32.PrivilegedServiceAuditAlarmW if unicode else advapi32.PrivilegedServiceAuditAlarmA
    PrivilegedServiceAuditAlarm.argtypes = [(LPCWSTR if unicode else LPSTR), (LPCWSTR if unicode else LPSTR), HANDLE, PPRIVILEGE_SET, WINBOOL]
    PrivilegedServiceAuditAlarm.restype = WINBOOL
    res = PrivilegedServiceAuditAlarm(SubsystemName, ServiceName, ClientToken, Privileges, AccessGranted)
    return win32_to_errcheck(res, errcheck)


def QuerySecurityAccessMask(SecurityInformation, DesiredAccess):
    QuerySecurityAccessMask = advapi32.QuerySecurityAccessMask
    QuerySecurityAccessMask.argtypes = [SECURITY_INFORMATION, LPDWORD]
    QuerySecurityAccessMask.restype = VOID
    res = QuerySecurityAccessMask(SecurityInformation, DesiredAccess)
    return res


def RevertToSelf(errcheck: bool = True):
    RevertToSelf = advapi32.RevertToSelf
    RevertToSelf.restype = WINBOOL
    res = RevertToSelf()
    return win32_to_errcheck(res, errcheck)


def SetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass, errcheck: bool = True):
    SetAclInformation = advapi32.SetAclInformation
    SetAclInformation.argtypes = [PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS]
    SetAclInformation.restype = WINBOOL
    res = SetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass)
    return win32_to_errcheck(res, errcheck)


def SetFileSecurity(lpFileName, SecurityInformation, pSecurityDescriptor, unicode: bool = True, errcheck: bool = True):
    SetFileSecurity = advapi32.SetFileSecurityW if unicode else advapi32.SetFileSecurityA
    SetFileSecurity.argtypes = [(LPCWSTR if unicode else LPSTR), SECURITY_INFORMATION, PSECURITY_DESCRIPTOR]
    SetFileSecurity.restype = WINBOOL
    res = SetFileSecurity(lpFileName, SecurityInformation, pSecurityDescriptor)
    return win32_to_errcheck(res, errcheck)


def SetPrivateObjectSecurity(SecurityInformation, ModificationDescriptor, ObjectsSecurityDescriptor, GenericMapping, Token, errcheck: bool = True):
    SetPrivateObjectSecurity = advapi32.SetPrivateObjectSecurity
    SetPrivateObjectSecurity.argtypes = [SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, POINTER(PSECURITY_DESCRIPTOR), PGENERIC_MAPPING, HANDLE]
    SetPrivateObjectSecurity.restype = WINBOOL
    res = SetPrivateObjectSecurity(SecurityInformation, ModificationDescriptor, ObjectsSecurityDescriptor, GenericMapping, Token)
    return win32_to_errcheck(res, errcheck)


def SetPrivateObjectSecurityEx(SecurityInformation, ModificationDescriptor, ObjectsSecurityDescriptor, AutoInheritFlags, GenericMapping, Token, errcheck: bool = True):
    SetPrivateObjectSecurityEx = advapi32.SetPrivateObjectSecurityEx
    SetPrivateObjectSecurityEx.argtypes = [SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, POINTER(PSECURITY_DESCRIPTOR), ULONG, PGENERIC_MAPPING, HANDLE]
    SetPrivateObjectSecurityEx.restype = WINBOOL
    res = SetPrivateObjectSecurityEx(SecurityInformation, ModificationDescriptor, ObjectsSecurityDescriptor, AutoInheritFlags, GenericMapping, Token)
    return win32_to_errcheck(res, errcheck)


def SetSecurityAccessMask(SecurityInformation, DesiredAccess):
    SetSecurityAccessMask = advapi32.SetSecurityAccessMask
    SetSecurityAccessMask.argtypes = [SECURITY_INFORMATION, LPDWORD]
    SetSecurityAccessMask.restype = VOID
    res = SetSecurityAccessMask(SecurityInformation, DesiredAccess)
    return res


def SetCachedSigningLevel(SourceFiles, SourceFileCount, Flags, TargetFile, errcheck: bool = True):
    SetCachedSigningLevel = advapi32.SetCachedSigningLevel
    SetCachedSigningLevel.argtypes = [PHANDLE, ULONG, ULONG, HANDLE]
    SetCachedSigningLevel.restype = WINBOOL
    res = SetCachedSigningLevel(SourceFiles, SourceFileCount, Flags, TargetFile)
    return win32_to_errcheck(res, errcheck)


def GetCachedSigningLevel(File, Flags, SigningLevel, Thumbprint, ThumbprintSize, ThumbprintAlgorithm, errcheck: bool = True):
    GetCachedSigningLevel = advapi32.GetCachedSigningLevel
    GetCachedSigningLevel.argtypes = [HANDLE, PULONG, PULONG, PUCHAR, PULONG, PULONG]
    GetCachedSigningLevel.restype = WINBOOL
    res = GetCachedSigningLevel(File, Flags, SigningLevel, Thumbprint, ThumbprintSize, ThumbprintAlgorithm)
    return win32_to_errcheck(res, errcheck)


def CheckTokenMembership(
    TokenHandle: int, 
    SidToCheck: Any, 
    IsMember: Any,
    errcheck: bool = True
) -> None:
    
    CheckTokenMembership = advapi32.CheckTokenMembership
    CheckTokenMembership.argtypes = [HANDLE, PVOID, PBOOL]
    CheckTokenMembership.restype = BOOL
    res = CheckTokenMembership(TokenHandle, SidToCheck, IsMember)
    return win32_to_errcheck(res, errcheck)


def CheckTokenMembershipEx(TokenHandle, SidToCheck, Flags, IsMember, errcheck: bool = True):
    CheckTokenMembershipEx = advapi32.CheckTokenMembershipEx
    CheckTokenMembershipEx.argtypes = [HANDLE, PSID, DWORD, PBOOL]
    CheckTokenMembershipEx.restype = WINBOOL
    res = CheckTokenMembershipEx(TokenHandle, SidToCheck, Flags, IsMember)
    return win32_to_errcheck(res, errcheck)


def AddAce(pAcl, dwAceRevision, dwStartingAceIndex, pAceList, nAceListLength, errcheck: bool = True):
    AddAce = advapi32.AddAce
    AddAce.argtypes = [PACL, DWORD, DWORD, LPVOID, DWORD]
    AddAce.restype = WINBOOL
    res = AddAce(pAcl, dwAceRevision, dwStartingAceIndex, pAceList, nAceListLength)
    return win32_to_errcheck(res, errcheck)


def AddAccessAllowedAce(pAcl, dwAceRevision, AccessMask, pSid, errcheck: bool = True):
    AddAccessAllowedAce = advapi32.AddAccessAllowedAce
    AddAccessAllowedAce.argtypes = [PACL, DWORD, DWORD, PSID]
    AddAccessAllowedAce.restype = WINBOOL
    res = AddAccessAllowedAce(pAcl, dwAceRevision, AccessMask, pSid)
    return win32_to_errcheck(res, errcheck)


def AddAccessAllowedAceEx(pAcl, dwAceRevision, AceFlags, AccessMask, pSid, errcheck: bool = True):
    AddAccessAllowedAceEx = advapi32.AddAccessAllowedAceEx
    AddAccessAllowedAceEx.argtypes = [PACL, DWORD, DWORD, DWORD, PSID]
    AddAccessAllowedAceEx.restype = WINBOOL
    res = AddAccessAllowedAceEx(pAcl, dwAceRevision, AceFlags, AccessMask, pSid)
    return win32_to_errcheck(res, errcheck)


def AdjustTokenGroups(TokenHandle, ResetToDefault, NewState, BufferLength, PreviousState, ReturnLength, errcheck: bool = True):
    AdjustTokenGroups = advapi32.AdjustTokenGroups
    AdjustTokenGroups.argtypes = [HANDLE, WINBOOL, PTOKEN_GROUPS, DWORD, PTOKEN_GROUPS, PDWORD]
    AdjustTokenGroups.restype = WINBOOL
    res = AdjustTokenGroups(TokenHandle, ResetToDefault, NewState, BufferLength, PreviousState, ReturnLength)
    return win32_to_errcheck(res, errcheck)


def AdjustTokenPrivileges(
    TokenHandle: int, 
    DisableAllPrivileges: bool, 
    NewState: Any, 
    BufferLength: int, 
    PreviousState: Any, 
    ReturnLength: int,
    errcheck: bool = True
) -> None:
    
    AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
    AdjustTokenPrivileges.argtypes = [
        HANDLE,
        WINBOOL,
        PTOKEN_PRIVILEGES,
        DWORD,
        PTOKEN_PRIVILEGES,
        PDWORD
    ]

    AdjustTokenPrivileges.restype = WINBOOL
    res = AdjustTokenPrivileges(
        TokenHandle, 
        DisableAllPrivileges, 
        NewState, 
        BufferLength, 
        PreviousState, 
        ReturnLength
    )

    return win32_to_errcheck(res, errcheck)


def AllocateAndInitializeSid(pIdentifierAuthority, nSubAuthorityCount, nSubAuthority0, nSubAuthority1, nSubAuthority2, nSubAuthority3, nSubAuthority4, nSubAuthority5, nSubAuthority6, nSubAuthority7, pSid, errcheck: bool = True):
    AllocateAndInitializeSid = advapi32.AllocateAndInitializeSid
    AllocateAndInitializeSid.argtypes = [PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, POINTER(PSID)]
    AllocateAndInitializeSid.restype = WINBOOL
    res = AllocateAndInitializeSid(pIdentifierAuthority, nSubAuthorityCount, nSubAuthority0, nSubAuthority1, nSubAuthority2, nSubAuthority3, nSubAuthority4, nSubAuthority5, nSubAuthority6, nSubAuthority7, pSid)
    return win32_to_errcheck(res, errcheck)


def AllocateLocallyUniqueId(errcheck: bool = True):
    AllocateLocallyUniqueId = advapi32.AllocateLocallyUniqueId
    AllocateLocallyUniqueId.restype = WINBOOL
    res = AllocateLocallyUniqueId()
    return win32_to_errcheck(res, errcheck)


def CopySid(nDestinationSidLength, pDestinationSid, pSourceSid, errcheck: bool = True):
    CopySid = advapi32.CopySid
    CopySid.argtypes = [DWORD, PSID, PSID]
    CopySid.restype = WINBOOL
    res = CopySid(nDestinationSidLength, pDestinationSid, pSourceSid)
    return win32_to_errcheck(res, errcheck)


def CreateWellKnownSid(WellKnownSidType, DomainSid, pSid, cbSid, errcheck: bool = True):
    CreateWellKnownSid = advapi32.CreateWellKnownSid
    CreateWellKnownSid.argtypes = [WELL_KNOWN_SID_TYPE, PSID, PSID, POINTER(DWORD)]
    CreateWellKnownSid.restype = WINBOOL
    res = CreateWellKnownSid(WellKnownSidType, DomainSid, pSid, cbSid)
    return win32_to_errcheck(res, errcheck)


def DeleteAce(pAcl, dwAceIndex, errcheck: bool = True):
    DeleteAce = advapi32.DeleteAce
    DeleteAce.argtypes = [PACL, DWORD]
    DeleteAce.restype = WINBOOL
    res = DeleteAce(pAcl, dwAceIndex)
    return win32_to_errcheck(res, errcheck)


def DuplicateToken(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle, errcheck: bool = True):
    DuplicateToken = advapi32.DuplicateToken
    DuplicateToken.argtypes = [HANDLE, SECURITY_IMPERSONATION_LEVEL, PHANDLE]
    DuplicateToken.restype = WINBOOL
    res = DuplicateToken(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle)
    return win32_to_errcheck(res, errcheck)


def DuplicateTokenEx(
    hExistingToken: int, 
    dwDesiredAccess: int, 
    lpTokenAttributes: Any, 
    ImpersonationLevel: int, 
    TokenType: int,
    phNewToken: Any,
    errcheck: bool = True
):
    
    DuplicateTokenEx = advapi32.DuplicateTokenEx
    DuplicateTokenEx.argtypes = [HANDLE, DWORD, VOID, UINT, UINT, HANDLE]
    DuplicateTokenEx.restype = BOOL
    res = DuplicateTokenEx(
        hExistingToken, 
        dwDesiredAccess, 
        lpTokenAttributes, 
        ImpersonationLevel, 
        TokenType, 
        phNewToken
    )

    return win32_to_errcheck(res, errcheck)


def EqualDomainSid(pSid1, pSid2, pfEqual, errcheck: bool = True):
    EqualDomainSid = advapi32.EqualDomainSid
    EqualDomainSid.argtypes = [PSID, PSID, POINTER(WINBOOL)]
    EqualDomainSid.restype = WINBOOL
    res = EqualDomainSid(pSid1, pSid2, pfEqual)
    return win32_to_errcheck(res, errcheck)


def FreeSid():
    FreeSid = advapi32.FreeSid
    FreeSid.restype = PVOID
    res = FreeSid()
    return res


def GetAce(pAcl, dwAceIndex, pAce, errcheck: bool = True):
    GetAce = advapi32.GetAce
    GetAce.argtypes = [PACL, DWORD, POINTER(LPVOID)]
    GetAce.restype = WINBOOL
    res = GetAce(pAcl, dwAceIndex, pAce)
    return win32_to_errcheck(res, errcheck)


def GetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass, errcheck: bool = True):
    GetAclInformation = advapi32.GetAclInformation
    GetAclInformation.argtypes = [PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS]
    GetAclInformation.restype = WINBOOL
    res = GetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass)
    return win32_to_errcheck(res, errcheck)


def GetKernelObjectSecurity(Handle, RequestedInformation, pSecurityDescriptor, nLength, lpnLengthNeeded, errcheck: bool = True):
    GetKernelObjectSecurity = advapi32.GetKernelObjectSecurity
    GetKernelObjectSecurity.argtypes = [HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, LPDWORD]
    GetKernelObjectSecurity.restype = WINBOOL
    res = GetKernelObjectSecurity(Handle, RequestedInformation, pSecurityDescriptor, nLength, lpnLengthNeeded)
    return win32_to_errcheck(res, errcheck)


def GetLengthSid():
    GetLengthSid = advapi32.GetLengthSid
    GetLengthSid.restype = DWORD
    res = GetLengthSid()
    return res


def GetSecurityDescriptorControl(pSecurityDescriptor, pControl, lpdwRevision, errcheck: bool = True):
    GetSecurityDescriptorControl = advapi32.GetSecurityDescriptorControl
    GetSecurityDescriptorControl.argtypes = [PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR_CONTROL, LPDWORD]
    GetSecurityDescriptorControl.restype = WINBOOL
    res = GetSecurityDescriptorControl(pSecurityDescriptor, pControl, lpdwRevision)
    return win32_to_errcheck(res, errcheck)


def GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted, errcheck: bool = True):
    GetSecurityDescriptorDacl = advapi32.GetSecurityDescriptorDacl
    GetSecurityDescriptorDacl.argtypes = [PSECURITY_DESCRIPTOR, LPBOOL, POINTER(PACL), LPBOOL]
    GetSecurityDescriptorDacl.restype = WINBOOL
    res = GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted)
    return win32_to_errcheck(res, errcheck)


def GetSecurityDescriptorGroup(pSecurityDescriptor, pGroup, lpbGroupDefaulted, errcheck: bool = True):
    GetSecurityDescriptorGroup = advapi32.GetSecurityDescriptorGroup
    GetSecurityDescriptorGroup.argtypes = [PSECURITY_DESCRIPTOR, POINTER(PSID), LPBOOL]
    GetSecurityDescriptorGroup.restype = WINBOOL
    res = GetSecurityDescriptorGroup(pSecurityDescriptor, pGroup, lpbGroupDefaulted)
    return win32_to_errcheck(res, errcheck)


def GetSecurityDescriptorLength():
    GetSecurityDescriptorLength = advapi32.GetSecurityDescriptorLength
    GetSecurityDescriptorLength.restype = DWORD
    res = GetSecurityDescriptorLength()
    return res


def GetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, lpbOwnerDefaulted, errcheck: bool = True):
    GetSecurityDescriptorOwner = advapi32.GetSecurityDescriptorOwner
    GetSecurityDescriptorOwner.argtypes = [PSECURITY_DESCRIPTOR, POINTER(PSID), LPBOOL]
    GetSecurityDescriptorOwner.restype = WINBOOL
    res = GetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, lpbOwnerDefaulted)
    return win32_to_errcheck(res, errcheck)


def GetSecurityDescriptorRMControl(SecurityDescriptor, RMControl):
    GetSecurityDescriptorRMControl = advapi32.GetSecurityDescriptorRMControl
    GetSecurityDescriptorRMControl.argtypes = [PSECURITY_DESCRIPTOR, PUCHAR]
    GetSecurityDescriptorRMControl.restype = DWORD
    res = GetSecurityDescriptorRMControl(SecurityDescriptor, RMControl)
    return res


def GetSecurityDescriptorSacl(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted, errcheck: bool = True):
    GetSecurityDescriptorSacl = advapi32.GetSecurityDescriptorSacl
    GetSecurityDescriptorSacl.argtypes = [PSECURITY_DESCRIPTOR, LPBOOL, POINTER(PACL), LPBOOL]
    GetSecurityDescriptorSacl.restype = WINBOOL
    res = GetSecurityDescriptorSacl(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted)
    return win32_to_errcheck(res, errcheck)


def GetSidIdentifierAuthority():
    GetSidIdentifierAuthority = advapi32.GetSidIdentifierAuthority
    GetSidIdentifierAuthority.restype = PSID_IDENTIFIER_AUTHORITY
    res = GetSidIdentifierAuthority()
    return res


def GetSidLengthRequired():
    GetSidLengthRequired = advapi32.GetSidLengthRequired
    GetSidLengthRequired.restype = DWORD
    res = GetSidLengthRequired()
    return res


def GetSidSubAuthority(pSid, nSubAuthority):
    GetSidSubAuthority = advapi32.GetSidSubAuthority
    GetSidSubAuthority.argtypes = [PSID, DWORD]
    GetSidSubAuthority.restype = PDWORD
    res = GetSidSubAuthority(pSid, nSubAuthority)
    return res


def GetSidSubAuthorityCount():
    GetSidSubAuthorityCount = advapi32.GetSidSubAuthorityCount
    GetSidSubAuthorityCount.restype = PUCHAR
    res = GetSidSubAuthorityCount()
    return res


def GetTokenInformation(
    TokenHandle: int, 
    TokenInformationClass: int,  
    TokenInformation: Any, 
    TokenInformationLength: int,
    ReturnLength: Any,
    errcheck: bool = True
):
    
    GetTokenInformation = advapi32.GetTokenInformation
    GetTokenInformation.argtypes = [
        HANDLE, 
        UINT, 
        LPVOID, 
        DWORD, 
        PDWORD
    ]

    GetTokenInformation.restype = BOOL
    res = GetTokenInformation(
        TokenHandle, 
        TokenInformationClass, 
        TokenInformation, 
        TokenInformationLength, 
        ReturnLength
    )
    
    return win32_to_errcheck(res, errcheck)


def GetWindowsAccountDomainSid(pSid, pDomainSid, cbDomainSid, errcheck: bool = True):
    GetWindowsAccountDomainSid = advapi32.GetWindowsAccountDomainSid
    GetWindowsAccountDomainSid.argtypes = [PSID, PSID, POINTER(DWORD)]
    GetWindowsAccountDomainSid.restype = WINBOOL
    res = GetWindowsAccountDomainSid(pSid, pDomainSid, cbDomainSid)
    return win32_to_errcheck(res, errcheck)


def InitializeAcl(pAcl, nAclLength, dwAclRevision, errcheck: bool = True):
    InitializeAcl = advapi32.InitializeAcl
    InitializeAcl.argtypes = [PACL, DWORD, DWORD]
    InitializeAcl.restype = WINBOOL
    res = InitializeAcl(pAcl, nAclLength, dwAclRevision)
    return win32_to_errcheck(res, errcheck)


def InitializeSecurityDescriptor(pSecurityDescriptor, dwRevision, errcheck: bool = True):
    InitializeSecurityDescriptor = advapi32.InitializeSecurityDescriptor
    InitializeSecurityDescriptor.argtypes = [PSECURITY_DESCRIPTOR, DWORD]
    InitializeSecurityDescriptor.restype = WINBOOL
    res = InitializeSecurityDescriptor(pSecurityDescriptor, dwRevision)
    return win32_to_errcheck(res, errcheck)


def InitializeSid(Sid, pIdentifierAuthority, nSubAuthorityCount, errcheck: bool = True):
    InitializeSid = advapi32.InitializeSid
    InitializeSid.argtypes = [PSID, PSID_IDENTIFIER_AUTHORITY, BYTE]
    InitializeSid.restype = WINBOOL
    res = InitializeSid(Sid, pIdentifierAuthority, nSubAuthorityCount)
    return win32_to_errcheck(res, errcheck)


def IsValidAcl():
    IsValidAcl = advapi32.IsValidAcl
    IsValidAcl.restype = WINBOOL
    res = IsValidAcl()
    return res


def IsValidSecurityDescriptor():
    IsValidSecurityDescriptor = advapi32.IsValidSecurityDescriptor
    IsValidSecurityDescriptor.restype = WINBOOL
    res = IsValidSecurityDescriptor()
    return res


def IsValidSid(pSid: int) -> int:
    IsValidSid = advapi32.IsValidSid
    IsValidSid.argtypes = [PSID]
    IsValidSid.restype = BOOL
    res = IsValidSid(pSid)
    return res


def IsWellKnownSid(pSid, WellKnownSidType):
    IsWellKnownSid = advapi32.IsWellKnownSid
    IsWellKnownSid.argtypes = [PSID, UINT]
    IsWellKnownSid.restype = WINBOOL
    res = IsWellKnownSid(pSid, WellKnownSidType)
    return res


def MakeAbsoluteSD(pSelfRelativeSecurityDescriptor, pAbsoluteSecurityDescriptor, lpdwAbsoluteSecurityDescriptorSize, pDacl, lpdwDaclSize, pSacl, lpdwSaclSize, pOwner, lpdwOwnerSize, pPrimaryGroup, lpdwPrimaryGroupSize, errcheck: bool = True):
    MakeAbsoluteSD = advapi32.MakeAbsoluteSD
    MakeAbsoluteSD.argtypes = [PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, LPDWORD, PACL, LPDWORD, PACL, LPDWORD, PSID, LPDWORD, PSID, LPDWORD]
    MakeAbsoluteSD.restype = WINBOOL
    res = MakeAbsoluteSD(pSelfRelativeSecurityDescriptor, pAbsoluteSecurityDescriptor, lpdwAbsoluteSecurityDescriptorSize, pDacl, lpdwDaclSize, pSacl, lpdwSaclSize, pOwner, lpdwOwnerSize, pPrimaryGroup, lpdwPrimaryGroupSize)
    return win32_to_errcheck(res, errcheck)


def MakeSelfRelativeSD(pAbsoluteSecurityDescriptor, pSelfRelativeSecurityDescriptor, lpdwBufferLength, errcheck: bool = True):
    MakeSelfRelativeSD = advapi32.MakeSelfRelativeSD
    MakeSelfRelativeSD.argtypes = [PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, LPDWORD]
    MakeSelfRelativeSD.restype = WINBOOL
    res = MakeSelfRelativeSD(pAbsoluteSecurityDescriptor, pSelfRelativeSecurityDescriptor, lpdwBufferLength)
    return win32_to_errcheck(res, errcheck)


def SetKernelObjectSecurity(Handle, SecurityInformation, SecurityDescriptor, errcheck: bool = True):
    SetKernelObjectSecurity = advapi32.SetKernelObjectSecurity
    SetKernelObjectSecurity.argtypes = [HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR]
    SetKernelObjectSecurity.restype = WINBOOL
    res = SetKernelObjectSecurity(Handle, SecurityInformation, SecurityDescriptor)
    return win32_to_errcheck(res, errcheck)


def SetSecurityDescriptorControl(pSecurityDescriptor, ControlBitsOfInterest, ControlBitsToSet, errcheck: bool = True):
    SetSecurityDescriptorControl = advapi32.SetSecurityDescriptorControl
    SetSecurityDescriptorControl.argtypes = [PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL, SECURITY_DESCRIPTOR_CONTROL]
    SetSecurityDescriptorControl.restype = WINBOOL
    res = SetSecurityDescriptorControl(pSecurityDescriptor, ControlBitsOfInterest, ControlBitsToSet)
    return win32_to_errcheck(res, errcheck)


def SetSecurityDescriptorDacl(pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted, errcheck: bool = True):
    SetSecurityDescriptorDacl = advapi32.SetSecurityDescriptorDacl
    SetSecurityDescriptorDacl.argtypes = [PSECURITY_DESCRIPTOR, WINBOOL, PACL, WINBOOL]
    SetSecurityDescriptorDacl.restype = WINBOOL
    res = SetSecurityDescriptorDacl(pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted)
    return win32_to_errcheck(res, errcheck)


def SetSecurityDescriptorGroup(pSecurityDescriptor, pGroup, bGroupDefaulted, errcheck: bool = True):
    SetSecurityDescriptorGroup = advapi32.SetSecurityDescriptorGroup
    SetSecurityDescriptorGroup.argtypes = [PSECURITY_DESCRIPTOR, PSID, WINBOOL]
    SetSecurityDescriptorGroup.restype = WINBOOL
    res = SetSecurityDescriptorGroup(pSecurityDescriptor, pGroup, bGroupDefaulted)
    return win32_to_errcheck(res, errcheck)


def SetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, bOwnerDefaulted, errcheck: bool = True):
    SetSecurityDescriptorOwner = advapi32.SetSecurityDescriptorOwner
    SetSecurityDescriptorOwner.argtypes = [PSECURITY_DESCRIPTOR, PSID, WINBOOL]
    SetSecurityDescriptorOwner.restype = WINBOOL
    res = SetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, bOwnerDefaulted)
    return win32_to_errcheck(res, errcheck)


def SetSecurityDescriptorRMControl(SecurityDescriptor, RMControl):
    SetSecurityDescriptorRMControl = advapi32.SetSecurityDescriptorRMControl
    SetSecurityDescriptorRMControl.argtypes = [PSECURITY_DESCRIPTOR, PUCHAR]
    SetSecurityDescriptorRMControl.restype = DWORD
    res = SetSecurityDescriptorRMControl(SecurityDescriptor, RMControl)
    return res


def SetSecurityDescriptorSacl(pSecurityDescriptor, bSaclPresent, pSacl, bSaclDefaulted, errcheck: bool = True):
    SetSecurityDescriptorSacl = advapi32.SetSecurityDescriptorSacl
    SetSecurityDescriptorSacl.argtypes = [PSECURITY_DESCRIPTOR, WINBOOL, PACL, WINBOOL]
    SetSecurityDescriptorSacl.restype = WINBOOL
    res = SetSecurityDescriptorSacl(pSecurityDescriptor, bSaclPresent, pSacl, bSaclDefaulted)
    return win32_to_errcheck(res, errcheck)


def SetTokenInformation(
    TokenHandle: int, 
    TokenInformationClass: int, 
    TokenInformation: Any, 
    TokenInformationLength: int,
    errcheck: bool = True
) -> None:
    
    SetTokenInformation = advapi32.SetTokenInformation
    SetTokenInformation.argtypes = [HANDLE, UINT, LPVOID, DWORD]
    SetTokenInformation.restype = BOOL
    res = SetTokenInformation(
        TokenHandle, 
        TokenInformationClass, 
        TokenInformation, 
        TokenInformationLength
    )

    return win32_to_errcheck(res, errcheck)


def AddMandatoryAce(pAcl, dwAceRevision, AceFlags, MandatoryPolicy, pLabelSid, errcheck: bool = True):
    AddMandatoryAce = advapi32.AddMandatoryAce
    AddMandatoryAce.argtypes = [PACL, DWORD, DWORD, DWORD, PSID]
    AddMandatoryAce.restype = WINBOOL
    res = AddMandatoryAce(pAcl, dwAceRevision, AceFlags, MandatoryPolicy, pLabelSid)
    return win32_to_errcheck(res, errcheck)


def CveEventWrite(CveId, AdditionalDetails, errcheck: bool = True):
    CveEventWrite = advapi32.CveEventWrite
    CveEventWrite.argtypes = [PCWSTR, PCWSTR]
    CveEventWrite.restype = LONG
    res = CveEventWrite(CveId, AdditionalDetails)
    return hresult_to_errcheck(res, errcheck)


def DeriveCapabilitySidsFromName(CapName, CapabilityGroupSids, CapabilityGroupSidCount, CapabilitySids, CapabilitySidCount, errcheck: bool = True):
    DeriveCapabilitySidsFromName = advapi32.DeriveCapabilitySidsFromName
    DeriveCapabilitySidsFromName.argtypes = [LPCWSTR, POINTER(PSID), POINTER(DWORD), POINTER(PSID), POINTER(DWORD)]
    DeriveCapabilitySidsFromName.restype = WINBOOL
    res = DeriveCapabilitySidsFromName(CapName, CapabilityGroupSids, CapabilityGroupSidCount, CapabilitySids, CapabilitySidCount)
    return win32_to_errcheck(res, errcheck)


def ImpersonateLoggedOnUser(hToken: int, errcheck: bool = True) -> None:
    ImpersonateLoggedOnUser = advapi32.ImpersonateLoggedOnUser
    ImpersonateLoggedOnUser.argtypes = [HANDLE]
    ImpersonateLoggedOnUser.restype = WINBOOL
    res = ImpersonateLoggedOnUser(hToken)
    return win32_to_errcheck(res, errcheck)    


def PrivilegeCheck(ClientToken, RequiredPrivileges, pfResult, errcheck: bool = True):
    PrivilegeCheck = advapi32.PrivilegeCheck
    PrivilegeCheck.argtypes = [HANDLE, PPRIVILEGE_SET, LPBOOL]
    PrivilegeCheck.restype = WINBOOL
    res = PrivilegeCheck(ClientToken, RequiredPrivileges, pfResult)
    return win32_to_errcheck(res, errcheck)

