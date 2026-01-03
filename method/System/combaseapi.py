# coding = 'utf-8'
# combaseapi.h

import enum
from typing import Any
from method.System.wtypesbase import *
from method.System.winusutypes import *
from method.System.public_dll import ole32
from method.System.unknwnbase import IUnknown
from method.System.errcheck import hresult_to_errcheck, win32_to_errcheck

interface = Structure
LPUNKNOWN = POINTER(IUnknown)


def LISet32(li, v) -> int:
    li.HighPart = LONG(v).value
    res = -1 if li.HighPart < 0 else 0
    li.LowPart = v
    return res


def ULISet32(li, v):
    li.HighPart = 0
    li.LowPart = v


CLSCTX_INPROC = (CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER)
CLSCTX_ALL = (CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER)
CLSCTX_SERVER = (CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER)

REGCLS_SINGLEUSE = 0
REGCLS_MULTIPLEUSE = 1
REGCLS_MULTI_SEPARATE = 2
REGCLS_SUSPENDED = 4
REGCLS_SURROGATE = 8

class tagREGCLS(enum.IntFlag):
    REGCLS_SINGLEUSE = 0
    REGCLS_MULTIPLEUSE = 1
    REGCLS_MULTI_SEPARATE = 2
    REGCLS_SUSPENDED = 4
    REGCLS_SURROGATE = 8

REGCLS = tagREGCLS

IRpcStubBuffer = IRpcStubBuffer = interface 
IRpcChannelBuffer = IRpcChannelBuffer = interface 

COINITBASE_MULTITHREADED = 0x0

class tagCOINITBASE(enum.IntFlag):
    COINITBASE_MULTITHREADED = 0x0

COINITBASE = tagCOINITBASE

class tagServerInformation(Structure):
    _fields_ = [('dwServerPid', DWORD),
                ('dwServerTid', DWORD),
                ('ui64ServerAddress', UINT64)
    ]

ServerInformation = tagServerInformation
PServerInformation = POINTER(ServerInformation)


def CreateStreamOnHGlobal(hGlobal, fDeleteOnRelease, ppstm, errcheck: bool = True):
    CreateStreamOnHGlobal = ole32.CreateStreamOnHGlobal
    '''
    CreateStreamOnHGlobal.argtypes = [
        HGLOBAL,
        WINBOOL,
        
    ]
    '''
    res = CreateStreamOnHGlobal(hGlobal, fDeleteOnRelease, ppstm)
    return hresult_to_errcheck(res, errcheck)    


def GetHGlobalFromStream(pstm, phglobal, errcheck: bool = True):
    GetHGlobalFromStream = ole32.GetHGlobalFromStream
    res = GetHGlobalFromStream(pstm, phglobal)
    return hresult_to_errcheck(res, errcheck)    


def CoInitialize(pvReserved: int = NULL, errcheck: bool = True) -> None:
    CoInitialize = ole32.CoInitialize
    CoInitialize.argtypes = [LPVOID]
    CoInitialize.restype = HRESULT
    res = CoInitialize(pvReserved)
    return hresult_to_errcheck(res, errcheck)


def CoInitializeEx(pvReserved: int, dwCoInit: int, errcheck: bool = True) -> None:
    CoInitializeEx = ole32.CoInitializeEx
    CoInitializeEx.argtypes = [REFIID, LPVOID]
    CoInitializeEx.restype = HRESULT
    res = CoInitializeEx(pvReserved, dwCoInit)
    return hresult_to_errcheck(res, errcheck)


def CoUninitialize(errcheck: bool = True) -> None:
    CoUninitialize = ole32.CoUninitialize
    CoUninitialize.restype = HRESULT
    res = CoUninitialize()
    return hresult_to_errcheck(res, errcheck)    


def CoGetCurrentLogicalThreadId(pguid, errcheck: bool = True):
    CoGetCurrentLogicalThreadId = ole32.CoGetCurrentLogicalThreadId
    CoGetCurrentLogicalThreadId.argtypes = [POINTER(GUID)]
    CoGetCurrentLogicalThreadId.restype = HRESULT
    res = CoGetCurrentLogicalThreadId(pguid)
    return hresult_to_errcheck(res, errcheck)    


def CoGetContextToken(pToken, errcheck: bool = True):
    CoGetContextToken = ole32.CoGetContextToken
    CoGetContextToken.argtypes = [PULONG_PTR]
    CoGetContextToken.restype = HRESULT
    res = CoGetContextToken(pToken)
    return hresult_to_errcheck(res, errcheck)    


def CoGetApartmentType(pAptType: int, pAptQualifier: int, errcheck: bool = True):
    CoGetApartmentType = ole32.CoGetApartmentType
    CoGetApartmentType.argtypes = [UINT, UINT]
    CoGetApartmentType.restype = HRESULT
    res = CoGetApartmentType(pAptType, pAptQualifier)
    return hresult_to_errcheck(res, errcheck)    


def CoGetObjectContext(riid, ppv, errcheck: bool = True):
    CoGetObjectContext = ole32.CoGetObjectContext
    CoGetObjectContext.argtypes = [REFIID, LPVOID]
    CoGetObjectContext.restype = HRESULT
    res = CoGetObjectContext(riid, ppv)
    return hresult_to_errcheck(res, errcheck)    


def CoRegisterClassObject(rclsid, pUnk, dwClsContext, flags, lpdwRegister, errcheck: bool = True):
    CoRegisterClassObject = ole32.CoRegisterClassObject
    CoRegisterClassObject.argtypes = [
        REFCLSID,
        LPUNKNOWN,
        DWORD,
        DWORD,
        LPDWORD
    ]

    CoRegisterClassObject.restype = HRESULT
    res = CoRegisterClassObject(rclsid, pUnk, dwClsContext, flags, lpdwRegister)
    return hresult_to_errcheck(res, errcheck)    


def CoRevokeClassObject(dwRegister, errcheck: bool = True):
    CoRevokeClassObject = ole32.CoRevokeClassObject
    res = CoRevokeClassObject(dwRegister)
    return hresult_to_errcheck(res, errcheck)    


def CoResumeClassObjects(errcheck: bool = True):
    CoResumeClassObjects = ole32.CoResumeClassObjects
    res = CoResumeClassObjects()
    return hresult_to_errcheck(res, errcheck)
    

def CoSuspendClassObjects(errcheck: bool = True):
    CoSuspendClassObjects = ole32.CoSuspendClassObjects
    res = CoSuspendClassObjects()
    return hresult_to_errcheck(res, errcheck)    

def CoGetMalloc(dwMemContext, ppMalloc, errcheck: bool = True):
    CoGetMalloc = ole32.CoGetMalloc
    res = CoGetMalloc(dwMemContext, ppMalloc)
    return hresult_to_errcheck(res, errcheck)    

def CoGetCurrentProcess():
    CoGetCurrentProcess = ole32.CoGetCurrentProcess
    CoGetCurrentProcess.restype = DWORD
    res = CoGetCurrentProcess()
    return res


def CoGetCallerTID(lpdwTID, errcheck: bool = True):
    CoGetCallerTID = ole32.CoGetCallerTID
    res = CoGetCallerTID(lpdwTID)
    return hresult_to_errcheck(res, errcheck)    

def CoGetDefaultContext(aptType, riid, ppv, errcheck: bool = True):
    CoGetDefaultContext = ole32.CoGetDefaultContext
    res = CoGetDefaultContext(aptType, riid, ppv)
    return hresult_to_errcheck(res, errcheck)    

def CoDecodeProxy(dwClientPid, ui64ProxyAddress, pServerInformation, errcheck: bool = True):
    CoDecodeProxy = ole32.CoDecodeProxy
    res = CoDecodeProxy(dwClientPid, ui64ProxyAddress, pServerInformation)
    return hresult_to_errcheck(res, errcheck)    

def CoWaitForMultipleObjects(dwFlags, dwTimeout, cHandles, pHandles, lpdwindex, errcheck: bool = True):
    CoWaitForMultipleObjects = ole32.CoWaitForMultipleObjects
    res = CoWaitForMultipleObjects(dwFlags, dwTimeout, cHandles, pHandles, lpdwindex)
    return hresult_to_errcheck(res, errcheck)    

def CoAllowUnmarshalerCLSID(clsid, errcheck: bool = True):
    CoAllowUnmarshalerCLSID = ole32.CoAllowUnmarshalerCLSID
    res = CoAllowUnmarshalerCLSID(clsid)
    return hresult_to_errcheck(res, errcheck)    

def CoGetClassObject(rclsid, dwClsContext, pvReserved, riid, ppv, errcheck: bool = True):
    CoGetClassObject = ole32.CoGetClassObject
    res = CoGetClassObject(rclsid, dwClsContext, pvReserved, riid, ppv)
    return hresult_to_errcheck(res, errcheck)    

def CoAddRefServerProcess():
    CoAddRefServerProcess = ole32.CoAddRefServerProcess
    res = CoAddRefServerProcess()
    return res


def CoReleaseServerProcess():
    CoReleaseServerProcess = ole32.CoReleaseServerProcess
    res = CoReleaseServerProcess()
    return res


def CoGetPSClsid(riid, pClsid, errcheck: bool = True):
    CoGetPSClsid = ole32.CoGetPSClsid
    res = CoGetPSClsid(riid, pClsid)
    return hresult_to_errcheck(res, errcheck)    

def CoRegisterPSClsid(riid, rclsid, errcheck: bool = True):
    CoRegisterPSClsid = ole32.CoRegisterPSClsid
    res = CoRegisterPSClsid(riid, rclsid)
    return hresult_to_errcheck(res, errcheck)    

def CoRegisterSurrogate(pSurrogate, errcheck: bool = True):
    CoRegisterSurrogate = ole32.CoRegisterSurrogate
    res = CoRegisterSurrogate(pSurrogate)
    return hresult_to_errcheck(res, errcheck)    

def CoMarshalHresult(pstm, phresult, errcheck: bool = True):
    CoMarshalHresult = ole32.CoMarshalHresult
    res = CoMarshalHresult(pstm, phresult)
    return hresult_to_errcheck(res, errcheck)    

def CoUnmarshalHresult(pstm, phresult, errcheck: bool = True):
    CoUnmarshalHresult = ole32.CoUnmarshalHresult
    res = CoUnmarshalHresult(pstm, phresult)
    return hresult_to_errcheck(res, errcheck)    

def CoLockObjectExternal(pUnk, fLock, fLastUnlockReleases, errcheck: bool = True):
    CoLockObjectExternal = ole32.CoLockObjectExternal
    res = CoLockObjectExternal(pUnk, fLock, fLastUnlockReleases)
    return hresult_to_errcheck(res, errcheck)
    

def CoGetStdMarshalEx(pUnkOuter, smexflags, ppUnkInner, errcheck: bool = True):
    CoGetStdMarshalEx = ole32.CoGetStdMarshalEx
    res = CoGetStdMarshalEx(pUnkOuter, smexflags, ppUnkInner)
    return hresult_to_errcheck(res, errcheck)    

def CoIncrementMTAUsage(pCookie, errcheck: bool = True):
    CoIncrementMTAUsage = ole32.CoIncrementMTAUsage
    res = CoIncrementMTAUsage(pCookie)
    return hresult_to_errcheck(res, errcheck)    

def CoDecrementMTAUsage(Cookie, errcheck: bool = True):
    CoDecrementMTAUsage = ole32.CoDecrementMTAUsage
    res = CoDecrementMTAUsage(Cookie)
    return hresult_to_errcheck(res, errcheck)

SMEXF_SERVER = 0x01
SMEXF_HANDLER = 0x02

class tagSTDMSHLFLAGS(enum.IntFlag):
    SMEXF_SERVER = 0x01
    SMEXF_HANDLER = 0x02

STDMSHLFLAGS = tagSTDMSHLFLAGS


def CoGetMarshalSizeMax(
    pulSize, 
    riid, 
    pUnk, 
    dwDestContext, 
    pvDestContext, 
    mshlflags,
    errcheck: bool = True
):
    
    CoGetMarshalSizeMax = ole32.CoGetMarshalSizeMax
    res = CoGetMarshalSizeMax(
        pulSize, 
        riid, 
        pUnk, 
        dwDestContext, 
        pvDestContext, 
        mshlflags
    )

    return hresult_to_errcheck(res, errcheck)    

def CoMarshalInterface(
    pStm, 
    riid, 
    pUnk, 
    dwDestContext, 
    pvDestContext, 
    mshlflags,
    errcheck: bool = True
):
    
    CoMarshalInterface = ole32.CoMarshalInterface
    res = CoMarshalInterface(
        pStm, 
        riid, 
        pUnk, 
        dwDestContext, 
        pvDestContext, 
        mshlflags
    )

    return hresult_to_errcheck(res, errcheck)    

def CoUnmarshalInterface(pStm, riid, ppv, errcheck: bool = True):
    CoUnmarshalInterface = ole32.CoUnmarshalInterface
    res = CoUnmarshalInterface(pStm, riid, ppv)
    return hresult_to_errcheck(res, errcheck)

def CoReleaseMarshalData(pStm, errcheck: bool = True):
    CoReleaseMarshalData = ole32.CoReleaseMarshalData
    res = CoReleaseMarshalData(pStm)
    return hresult_to_errcheck(res, errcheck)    

def CoDisconnectObject(pUnk, dwReserved, errcheck: bool = True):
    CoDisconnectObject = ole32.CoDisconnectObject
    res = CoDisconnectObject(pUnk, dwReserved)
    return hresult_to_errcheck(res, errcheck)    

def CoGetStandardMarshal(
    riid, 
    pUnk, 
    dwDestContext, 
    pvDestContext, 
    mshlflags, 
    ppMarshal,
    errcheck: bool = True
):
    
    CoGetStandardMarshal = ole32.CoGetStandardMarshal
    res = CoGetStandardMarshal(riid, 
                               pUnk, 
                               dwDestContext, 
                               pvDestContext, 
                               mshlflags, 
                               ppMarshal
    )

    return hresult_to_errcheck(res, errcheck)    

def CoMarshalInterThreadInterfaceInStream(riid, pUnk, ppStm, errcheck: bool = True):
    CoMarshalInterThreadInterfaceInStream = ole32.CoMarshalInterThreadInterfaceInStream
    res = CoMarshalInterThreadInterfaceInStream(riid, pUnk, ppStm)
    return hresult_to_errcheck(res, errcheck)    

def CoGetInterfaceAndReleaseStream(pStm, iid, ppv, errcheck: bool = True):
    CoGetInterfaceAndReleaseStream = ole32.CoGetInterfaceAndReleaseStream
    res = CoGetInterfaceAndReleaseStream(pStm, iid, ppv)
    return hresult_to_errcheck(res, errcheck)    

def CoCreateFreeThreadedMarshaler(punkOuter, ppunkMarshal, errcheck: bool = True):
    CoCreateFreeThreadedMarshaler = ole32.CoCreateFreeThreadedMarshaler
    res = CoCreateFreeThreadedMarshaler(punkOuter, ppunkMarshal)
    return hresult_to_errcheck(res, errcheck)    

def CoFreeUnusedLibraries():
    CoFreeUnusedLibraries = ole32.CoFreeUnusedLibraries
    res = CoFreeUnusedLibraries()
    return res


def CoFreeUnusedLibrariesEx(dwUnloadDelay, dwReserved):
    CoFreeUnusedLibrariesEx = ole32.CoFreeUnusedLibrariesEx
    res = CoFreeUnusedLibrariesEx()
    return res


def CoInitializeSecurity(
    pSecDesc, 
    cAuthSvc, 
    asAuthSvc, 
    pReserved1, 
    dwAuthnLevel, 
    dwImpLevel, 
    pAuthList, 
    dwCapabilities, 
    pReserved3,
    errcheck: bool = True
):

    CoInitializeSecurity = ole32.CoInitializeSecurity
    res = CoInitializeSecurity(
        pSecDesc, 
        cAuthSvc, 
        asAuthSvc, 
        pReserved1, 
        dwAuthnLevel, 
        dwImpLevel, 
        pAuthList, 
        dwCapabilities, 
        pReserved3
    )

    return hresult_to_errcheck(res, errcheck)

def CoSwitchCallContext(pNewObject, ppOldObject, errcheck: bool = True):
    CoSwitchCallContext = ole32.CoSwitchCallContext
    res = CoSwitchCallContext(pNewObject, ppOldObject)
    return hresult_to_errcheck(res, errcheck)

COM_RIGHTS_EXECUTE = 1
COM_RIGHTS_EXECUTE_LOCAL = 2
COM_RIGHTS_EXECUTE_REMOTE = 4
COM_RIGHTS_ACTIVATE_LOCAL = 8
COM_RIGHTS_ACTIVATE_REMOTE = 16


def CoCreateInstanceFromApp(
    Clsid, 
    punkOuter, 
    dwClsCtx, 
    reserved, 
    dwCount, 
    pResults,
    errcheck: bool = True
):
    
    CoCreateInstanceFromApp = ole32.CoCreateInstanceFromApp
    res = CoCreateInstanceFromApp(
        Clsid, 
        punkOuter, 
        dwClsCtx, 
        reserved, 
        dwCount, 
        pResults
    )

    return hresult_to_errcheck(res, errcheck)    

def CoIsHandlerConnected(pUnk, errcheck: bool = True):
    CoIsHandlerConnected = ole32.CoIsHandlerConnected
    res = CoIsHandlerConnected(pUnk)
    return hresult_to_errcheck(res, errcheck)    

def CoDisconnectContext(dwTimeout, errcheck: bool = True):
    CoDisconnectContext = ole32.CoDisconnectContext
    res = CoDisconnectContext(dwTimeout)
    return hresult_to_errcheck(res, errcheck)    

def CoGetCallContext(riid, ppInterface, errcheck: bool = True):
    CoGetCallContext = ole32.CoGetCallContext
    res = CoGetCallContext(riid, ppInterface)
    return hresult_to_errcheck(res, errcheck)    

def CoQueryProxyBlanket(
    pProxy, 
    pwAuthnSvc, 
    pAuthzSvc, 
    pServerPrincName, 
    pAuthnLevel, 
    pImpLevel, 
    pAuthInfo, 
    pCapabilites,
    errcheck: bool = True
):
    
    CoQueryProxyBlanket = ole32.CoQueryProxyBlanket
    res = CoQueryProxyBlanket(
        pProxy, 
        pwAuthnSvc, 
        pAuthzSvc, 
        pServerPrincName, 
        pAuthnLevel, 
        pImpLevel, 
        pAuthInfo, 
        pCapabilites
    )

    return hresult_to_errcheck(res, errcheck)    

def CoSetProxyBlanket(
    pProxy, 
    dwAuthnSvc, 
    dwAuthzSvc, 
    pServerPrincName, 
    dwAuthnLevel, 
    dwImpLevel, 
    pAuthInfo, 
    dwCapabilities,
    errcheck: bool = True
    ):
    
    CoSetProxyBlanket = ole32.CoSetProxyBlanket
    res = CoSetProxyBlanket(
        pProxy, 
        dwAuthnSvc, 
        dwAuthzSvc, 
        pServerPrincName, 
        dwAuthnLevel, 
        dwImpLevel, 
        pAuthInfo, 
        dwCapabilities
    )

    return hresult_to_errcheck(res, errcheck)    


def CoCopyProxy(pProxy, ppCopy, errcheck: bool = True):
    CoCopyProxy = ole32.CoCopyProxy
    res = CoCopyProxy(pProxy, ppCopy)
    return hresult_to_errcheck(res, errcheck)    


def CoQueryClientBlanket(
    pAuthnSvc, 
    pAuthzSvc, 
    pServerPrincName, 
    pAuthnLevel, 
    pImpLevel, 
    pPrivs, 
    pCapabilities,
    errcheck: bool = True    
):
    
    CoQueryClientBlanket = ole32.CoQueryClientBlanket
    res = CoQueryClientBlanket(
        pAuthnSvc, 
        pAuthzSvc, 
        pServerPrincName, 
        pAuthnLevel, 
        pImpLevel, 
        pPrivs, 
        pCapabilities
    )

    return hresult_to_errcheck(res, errcheck)    

def CoImpersonateClient():
    CoImpersonateClient = ole32.CoImpersonateClient
    res = CoImpersonateClient()
    return res


def CoRevertToSelf():
    CoRevertToSelf = ole32.CoRevertToSelf
    res = CoRevertToSelf()
    return res


def CoQueryAuthenticationServices(pcAuthSvc, asAuthSvc, errcheck: bool = True):
    CoQueryAuthenticationServices = ole32.CoQueryAuthenticationServices
    res = CoQueryAuthenticationServices(pcAuthSvc, asAuthSvc)
    return hresult_to_errcheck(res, errcheck)    

def CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv, errcheck: bool = True):
    CoCreateInstance = ole32.CoCreateInstance
    res = CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv)
    return hresult_to_errcheck(res, errcheck)    

def CoCreateInstanceEx(Clsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults, errcheck: bool = True):
    CoCreateInstanceEx = ole32.CoCreateInstanceEx
    res = CoCreateInstanceEx(Clsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults)
    return hresult_to_errcheck(res, errcheck)    

def CoGetCancelObject(dwThreadId, iid, ppUnk, errcheck: bool = True):
    CoGetCancelObject = ole32.CoGetCancelObject
    res = CoGetCancelObject(dwThreadId, iid, ppUnk)
    return hresult_to_errcheck(res, errcheck)    

def CoSetCancelObject(pUnk, errcheck: bool = True):
    CoSetCancelObject = ole32.CoSetCancelObject
    res = CoSetCancelObject(pUnk)
    return hresult_to_errcheck(res, errcheck)    

def CoCancelCall(dwThreadId, ulTimeout, errcheck: bool = True):
    CoCancelCall = ole32.CoCancelCall
    res = CoCancelCall(dwThreadId, ulTimeout)
    return hresult_to_errcheck(res, errcheck)    

def CoTestCancel():
    CoTestCancel = ole32.CoTestCancel
    res = CoTestCancel()
    return res


def CoEnableCallCancellation(pReserved, errcheck: bool = True):
    CoEnableCallCancellation = ole32.CoEnableCallCancellation
    res = CoEnableCallCancellation(pReserved)
    return hresult_to_errcheck(res, errcheck)    

def CoDisableCallCancellation(pReserved, errcheck: bool = True):
    CoDisableCallCancellation = ole32.CoDisableCallCancellation
    res = CoDisableCallCancellation(pReserved)
    return hresult_to_errcheck(res, errcheck)    

def StringFromCLSID(rclsid: Any, lplpsz: Any, errcheck: bool = True) -> None:
    StringFromCLSID = ole32.StringFromCLSID
    res = StringFromCLSID(rclsid, lplpsz)
    return hresult_to_errcheck(res, errcheck)

def CLSIDFromString(lpsz: str, pclsid: Any, errcheck: bool = True) -> None:
    CLSIDFromString = ole32.CLSIDFromString
    res = CLSIDFromString(lpsz, pclsid)
    return hresult_to_errcheck(res, errcheck)

def StringFromIID(rclsid, lplpsz, errcheck: bool = True):
    StringFromIID = ole32.StringFromIID
    res = StringFromIID(rclsid, lplpsz)
    return hresult_to_errcheck(res, errcheck)    

def IIDFromString(lpsz, lpiid, errcheck: bool = True):
    IIDFromString = ole32.IIDFromString
    res = IIDFromString(lpsz, lpiid)
    return hresult_to_errcheck(res, errcheck)    

def ProgIDFromCLSID(clsid, lplpszProgID, errcheck: bool = True):
    ProgIDFromCLSID = ole32.ProgIDFromCLSID
    res = ProgIDFromCLSID(clsid, lplpszProgID)
    return hresult_to_errcheck(res, errcheck)    

def CLSIDFromProgID(lpszProgID, lpclsid, errcheck: bool = True):
    CLSIDFromProgID = ole32.CLSIDFromProgID
    res = CLSIDFromProgID(lpszProgID, lpclsid)
    return hresult_to_errcheck(res, errcheck)    

def StringFromGUID2(rguid: Any, lpsz: Any, cchMax: int, errcheck: bool = True) -> None:
    StringFromGUID2 = ole32.StringFromGUID2
    res = StringFromGUID2(rguid, lpsz, cchMax)
    return hresult_to_errcheck(res, errcheck)
    

def CoCreateGuid(pguid, errcheck: bool = True):
    CoCreateGuid = ole32.CoCreateGuid
    res = CoCreateGuid(pguid)
    return hresult_to_errcheck(res, errcheck)    

class tagPROPVARIANT(Structure):
    pass

PROPVARIANT = tagPROPVARIANT


def PropVariantCopy(pvarDest, pvarSrc, errcheck: bool = True):
    PropVariantCopy = ole32.PropVariantCopy
    res = PropVariantCopy(pvarDest, pvarSrc)
    return hresult_to_errcheck(res, errcheck)    

def PropVariantClear(pvar, errcheck: bool = True):
    PropVariantClear = ole32.PropVariantClear
    res = PropVariantClear(pvar)
    return hresult_to_errcheck(res, errcheck)    

def FreePropVariantArray(cVariants, rgvars, errcheck: bool = True):
    FreePropVariantArray = ole32.FreePropVariantArray
    res = FreePropVariantArray(cVariants, rgvars)
    return hresult_to_errcheck(res, errcheck)    

def CoWaitForMultipleHandles(dwFlags, dwTimeout, cHandles, pHandles, lpdwindex, errcheck: bool = True):
    CoWaitForMultipleHandles = ole32.CoWaitForMultipleHandles
    res = CoWaitForMultipleHandles(dwFlags, dwTimeout, cHandles, pHandles, lpdwindex)
    return hresult_to_errcheck(res, errcheck)    

COWAIT_DEFAULT = 0
COWAIT_WAITALL = 1
COWAIT_ALERTABLE = 2
COWAIT_INPUTAVAILABLE = 4
COWAIT_DISPATCH_CALLS = 8
COWAIT_DISPATCH_WINDOW_MESSAGES = 0x10

class tagCOWAIT_FLAGS(enum.IntFlag):
    COWAIT_DEFAULT = 0
    COWAIT_WAITALL = 1
    COWAIT_ALERTABLE = 2
    COWAIT_INPUTAVAILABLE = 4
    COWAIT_DISPATCH_CALLS = 8
    COWAIT_DISPATCH_WINDOW_MESSAGES = 0x10

COWAIT_FLAGS = tagCOWAIT_FLAGS

CWMO_DEFAULT = 0
CWMO_DISPATCH_CALLS = 1
CWMO_DISPATCH_WINDOW_MESSAGES = 2

class CWMO_FLAGS(enum.IntFlag):
    CWMO_DEFAULT = 0
    CWMO_DISPATCH_CALLS = 1
    CWMO_DISPATCH_WINDOW_MESSAGES = 2

CWMO_MAX_HANDLES = 56


def CoGetTreatAsClass(clsidOld, pClsidNew, errcheck: bool = True):
    CoGetTreatAsClass = ole32.CoGetTreatAsClass
    res = CoGetTreatAsClass(clsidOld, pClsidNew)
    return hresult_to_errcheck(res, errcheck)    

def CoInvalidateRemoteMachineBindings(pszMachineName, errcheck: bool = True):
    CoInvalidateRemoteMachineBindings = ole32.CoInvalidateRemoteMachineBindings
    res = CoInvalidateRemoteMachineBindings(pszMachineName)
    return hresult_to_errcheck(res, errcheck)    

def DllGetClassObject(rclsid, riid, ppv, errcheck: bool = True):
    DllGetClassObject = ole32.DllGetClassObject
    res = DllGetClassObject(rclsid, riid, ppv)
    return hresult_to_errcheck(res, errcheck)    

def DllCanUnloadNow():
    DllCanUnloadNow = ole32.DllCanUnloadNow
    res = DllCanUnloadNow()
    return res


def CoTaskMemAlloc(cb, errcheck: bool = True):
    CoTaskMemAlloc = ole32.CoTaskMemAlloc
    res = CoTaskMemAlloc(cb)
    return win32_to_errcheck(res, errcheck)    

def CoTaskMemRealloc(pv, cb, errcheck: bool = True):
    CoTaskMemRealloc = ole32.CoTaskMemRealloc
    res = CoTaskMemRealloc(pv, cb)
    return win32_to_errcheck(res, errcheck)

def CoTaskMemFree(pv):
    CoTaskMemFree = ole32.CoTaskMemFree
    CoTaskMemFree(pv)