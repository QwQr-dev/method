# coding = 'utf-8'
# combaseapi.h

import enum
from typing import Any
from ctypes import Structure, POINTER, WinError

try:
    from wtypesbase import *
    from public_dll import ole32
    from win_cbasictypes import *
    from error import GetLastError
    from winerror import S_OK, FAILED
except ImportError:
    from .wtypesbase import *
    from .public_dll import ole32
    from .win_cbasictypes import *
    from .error import GetLastError
    from .winerror import S_OK, FAILED

NULL = 0
interface = Structure


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


def CreateStreamOnHGlobal(hGlobal, fDeleteOnRelease, ppstm):
    CreateStreamOnHGlobal = ole32.CreateStreamOnHGlobal
    res = CreateStreamOnHGlobal(hGlobal, fDeleteOnRelease, ppstm)
    if res != S_OK:
        raise WinError(res)
    

def GetHGlobalFromStream(pstm, phglobal):
    GetHGlobalFromStream = ole32.GetHGlobalFromStream
    res = GetHGlobalFromStream(pstm, phglobal)
    if res != S_OK:
        raise WinError(res)
    

def CoInitialize(pvReserved: int = NULL) -> None:
    CoInitialize = ole32.CoInitialize
    res = CoInitialize(pvReserved)
    if FAILED(res):
        raise WinError(res)


def CoInitializeEx(pvReserved: int, dwCoInit: int) -> None:
    CoInitializeEx = ole32.CoInitializeEx
    res = CoInitializeEx(pvReserved, dwCoInit)
    if FAILED(res):
        raise WinError(res)


def CoUninitialize() -> None:
    CoUninitialize = ole32.CoUninitialize
    res = CoUninitialize()
    if FAILED(res):
        raise WinError(res)
    

def CoGetCurrentLogicalThreadId(pguid):
    CoGetCurrentLogicalThreadId = ole32.CoGetCurrentLogicalThreadId
    res = CoGetCurrentLogicalThreadId(pguid)
    if res != S_OK:
        raise WinError(res)
    

def CoGetContextToken(pToken):
    CoGetContextToken = ole32.CoGetContextToken
    res = CoGetContextToken(pToken)
    if res != S_OK:
        raise WinError(res)
    

def CoGetApartmentType(pAptType, pAptQualifier):
    CoGetApartmentType = ole32.CoGetApartmentType
    res = CoGetApartmentType(pAptType, pAptQualifier)
    if res != S_OK:
        raise WinError(res)
    

def CoGetObjectContext(riid, ppv):
    CoGetObjectContext = ole32.CoGetObjectContext
    res = CoGetObjectContext(riid, ppv)
    if res != S_OK:
        raise WinError(res)
    

def CoRegisterClassObject(rclsid, pUnk, dwClsContext, flags, lpdwRegister):
    CoRegisterClassObject = ole32.CoRegisterClassObject
    res = CoRegisterClassObject(rclsid, pUnk, dwClsContext, flags, lpdwRegister)
    if res != S_OK:
        raise WinError(res)
    

def CoRevokeClassObject(dwRegister):
    CoRevokeClassObject = ole32.CoRevokeClassObject
    res = CoRevokeClassObject(dwRegister)
    if res != S_OK:
        raise WinError(res)
    

def CoResumeClassObjects():
    CoResumeClassObjects = ole32.CoResumeClassObjects
    res = CoResumeClassObjects()
    if res != S_OK:
        raise WinError()
    

def CoSuspendClassObjects():
    CoSuspendClassObjects = ole32.CoSuspendClassObjects
    res = CoSuspendClassObjects()
    if res != S_OK:
        raise WinError(res)
    

def CoGetMalloc(dwMemContext, ppMalloc):
    CoGetMalloc = ole32.CoGetMalloc
    res = CoGetMalloc(dwMemContext, ppMalloc)
    if res != S_OK:
        raise WinError(res)
    

def CoGetCurrentProcess():
    CoGetCurrentProcess = ole32.CoGetCurrentProcess
    res = CoGetCurrentProcess()
    return res


def CoGetCallerTID(lpdwTID):
    CoGetCallerTID = ole32.CoGetCallerTID
    res = CoGetCallerTID(lpdwTID)
    if res != S_OK:
        raise WinError(res)
    

def CoGetDefaultContext(aptType, riid, ppv):
    CoGetDefaultContext = ole32.CoGetDefaultContext
    res = CoGetDefaultContext(aptType, riid, ppv)
    if res != S_OK:
        raise WinError(res)
    

def CoDecodeProxy(dwClientPid, ui64ProxyAddress, pServerInformation):
    CoDecodeProxy = ole32.CoDecodeProxy
    res = CoDecodeProxy(dwClientPid, ui64ProxyAddress, pServerInformation)
    if res != S_OK:
        raise WinError(res)
    

def CoWaitForMultipleObjects(dwFlags, dwTimeout, cHandles, pHandles, lpdwindex):
    CoWaitForMultipleObjects = ole32.CoWaitForMultipleObjects
    res = CoWaitForMultipleObjects(dwFlags, dwTimeout, cHandles, pHandles, lpdwindex)
    if res != S_OK:
        raise WinError(res)
    

def CoAllowUnmarshalerCLSID(clsid):
    CoAllowUnmarshalerCLSID = ole32.CoAllowUnmarshalerCLSID
    res = CoAllowUnmarshalerCLSID(clsid)
    if res != S_OK:
        raise WinError(res)
    

def CoGetClassObject(rclsid, dwClsContext, pvReserved, riid, ppv):
    CoGetClassObject = ole32.CoGetClassObject
    res = CoGetClassObject(rclsid, dwClsContext, pvReserved, riid, ppv)
    if res != S_OK:
        raise WinError(res)
    

def CoAddRefServerProcess():
    CoAddRefServerProcess = ole32.CoAddRefServerProcess
    res = CoAddRefServerProcess()
    return res


def CoReleaseServerProcess():
    CoReleaseServerProcess = ole32.CoReleaseServerProcess
    res = CoReleaseServerProcess()
    return res


def CoGetPSClsid(riid, pClsid):
    CoGetPSClsid = ole32.CoGetPSClsid
    res = CoGetPSClsid(riid, pClsid)
    if res != S_OK:
        raise WinError(res)
    

def CoRegisterPSClsid(riid, rclsid):
    CoRegisterPSClsid = ole32.CoRegisterPSClsid
    res = CoRegisterPSClsid(riid, rclsid)
    if res != S_OK:
        raise WinError(res)
    

def CoRegisterSurrogate(pSurrogate):
    CoRegisterSurrogate = ole32.CoRegisterSurrogate
    res = CoRegisterSurrogate(pSurrogate)
    if res != S_OK:
        raise WinError(res)
    

def CoMarshalHresult(pstm, phresult):
    CoMarshalHresult = ole32.CoMarshalHresult
    res = CoMarshalHresult(pstm, phresult)
    if res != S_OK:
        raise WinError(res)
    

def CoUnmarshalHresult(pstm, phresult):
    CoUnmarshalHresult = ole32.CoUnmarshalHresult
    res = CoUnmarshalHresult(pstm, phresult)
    if res != S_OK:
        raise WinError(res)
    

def CoLockObjectExternal(pUnk, fLock, fLastUnlockReleases):
    CoLockObjectExternal = ole32.CoLockObjectExternal
    res = CoLockObjectExternal(pUnk, fLock, fLastUnlockReleases)
    if res !=S_OK:
        raise WinError(res)
    

def CoGetStdMarshalEx(pUnkOuter, smexflags, ppUnkInner):
    CoGetStdMarshalEx = ole32.CoGetStdMarshalEx
    res = CoGetStdMarshalEx(pUnkOuter, smexflags, ppUnkInner)
    if res != S_OK:
        raise WinError(res)
    

def CoIncrementMTAUsage(pCookie):
    CoIncrementMTAUsage = ole32.CoIncrementMTAUsage
    res = CoIncrementMTAUsage(pCookie)
    if res != S_OK:
        raise WinError(res)
    

def CoDecrementMTAUsage(Cookie):
    CoDecrementMTAUsage = ole32.CoDecrementMTAUsage
    res = CoDecrementMTAUsage(Cookie)
    if res != S_OK:
        raise WinError(res)


SMEXF_SERVER = 0x01
SMEXF_HANDLER = 0x02

class tagSTDMSHLFLAGS(enum.IntFlag):
    SMEXF_SERVER = 0x01
    SMEXF_HANDLER = 0x02

STDMSHLFLAGS = tagSTDMSHLFLAGS


def CoGetMarshalSizeMax(pulSize, 
                        riid, 
                        pUnk, 
                        dwDestContext, 
                        pvDestContext, 
                        mshlflags):
    
    CoGetMarshalSizeMax = ole32.CoGetMarshalSizeMax
    res = CoGetMarshalSizeMax(pulSize, 
                              riid, 
                              pUnk, 
                              dwDestContext, 
                              pvDestContext, 
                              mshlflags
    )

    if res != S_OK:
        raise WinError(res)
    

def CoMarshalInterface(pStm, 
                       riid, 
                       pUnk, 
                       dwDestContext, 
                       pvDestContext, 
                       mshlflags):
    
    CoMarshalInterface = ole32.CoMarshalInterface
    res = CoMarshalInterface(pStm, 
                             riid, 
                             pUnk, 
                             dwDestContext, 
                             pvDestContext, 
                             mshlflags
    )

    if res != S_OK:
        raise WinError(res)
    

def CoUnmarshalInterface(pStm, riid, ppv):
    CoUnmarshalInterface = ole32.CoUnmarshalInterface
    res = CoUnmarshalInterface(pStm, riid, ppv)
    if res != S_OK:
        raise WinError(res)


def CoReleaseMarshalData(pStm):
    CoReleaseMarshalData = ole32.CoReleaseMarshalData
    res = CoReleaseMarshalData(pStm)
    if res != S_OK:
        raise WinError(res)
    

def CoDisconnectObject(pUnk, dwReserved):
    CoDisconnectObject = ole32.CoDisconnectObject
    res = CoDisconnectObject(pUnk, dwReserved)
    if res != S_OK:
        raise WinError(res)
    

def CoGetStandardMarshal(riid, 
                         pUnk, 
                         dwDestContext, 
                         pvDestContext, 
                         mshlflags, 
                         ppMarshal):
    
    CoGetStandardMarshal = ole32.CoGetStandardMarshal
    res = CoGetStandardMarshal(riid, 
                               pUnk, 
                               dwDestContext, 
                               pvDestContext, 
                               mshlflags, 
                               ppMarshal
    )

    if res != S_OK:
        raise WinError(res)
    

def CoMarshalInterThreadInterfaceInStream(riid, pUnk, ppStm):
    CoMarshalInterThreadInterfaceInStream = ole32.CoMarshalInterThreadInterfaceInStream
    res = CoMarshalInterThreadInterfaceInStream(riid, pUnk, ppStm)
    if res != S_OK:
        raise WinError(res)
    

def CoGetInterfaceAndReleaseStream(pStm, iid, ppv):
    CoGetInterfaceAndReleaseStream = ole32.CoGetInterfaceAndReleaseStream
    res = CoGetInterfaceAndReleaseStream(pStm, iid, ppv)
    if res != S_OK:
        raise WinError(res)
    

def CoCreateFreeThreadedMarshaler(punkOuter, ppunkMarshal):
    CoCreateFreeThreadedMarshaler = ole32.CoCreateFreeThreadedMarshaler
    res = CoCreateFreeThreadedMarshaler(punkOuter, ppunkMarshal)
    if res != S_OK:
        raise WinError(res)
    

def CoFreeUnusedLibraries():
    CoFreeUnusedLibraries = ole32.CoFreeUnusedLibraries
    res = CoFreeUnusedLibraries()
    return res


def CoFreeUnusedLibrariesEx(dwUnloadDelay, dwReserved):
    CoFreeUnusedLibrariesEx = ole32.CoFreeUnusedLibrariesEx
    res = CoFreeUnusedLibrariesEx()
    return res


def CoInitializeSecurity(pSecDesc, 
                         cAuthSvc, 
                         asAuthSvc, 
                         pReserved1, 
                         dwAuthnLevel, 
                         dwImpLevel, 
                         pAuthList, 
                         dwCapabilities, 
                         pReserved3):
    
    CoInitializeSecurity = ole32.CoInitializeSecurity
    res = CoInitializeSecurity(pSecDesc, 
                               cAuthSvc, 
                               asAuthSvc, 
                               pReserved1, 
                               dwAuthnLevel, 
                               dwImpLevel, 
                               pAuthList, 
                               dwCapabilities, 
                               pReserved3
    )

    if res != S_OK:
        raise WinError(res)


def CoSwitchCallContext(pNewObject, ppOldObject):
    CoSwitchCallContext = ole32.CoSwitchCallContext
    res = CoSwitchCallContext(pNewObject, ppOldObject)
    if res != S_OK:
        raise WinError(res)


COM_RIGHTS_EXECUTE = 1
COM_RIGHTS_EXECUTE_LOCAL = 2
COM_RIGHTS_EXECUTE_REMOTE = 4
COM_RIGHTS_ACTIVATE_LOCAL = 8
COM_RIGHTS_ACTIVATE_REMOTE = 16


def CoCreateInstanceFromApp(Clsid, 
                            punkOuter, 
                            dwClsCtx, 
                            reserved, 
                            dwCount, 
                            pResults):
    
    CoCreateInstanceFromApp = ole32.CoCreateInstanceFromApp
    res = CoCreateInstanceFromApp(Clsid, 
                                  punkOuter, 
                                  dwClsCtx, 
                                  reserved, 
                                  dwCount, 
                                  pResults
    )

    if res != S_OK:
        raise WinError(res)
    

def CoIsHandlerConnected(pUnk):
    CoIsHandlerConnected = ole32.CoIsHandlerConnected
    res = CoIsHandlerConnected(pUnk)
    if res != S_OK:
        raise WinError(res)
    

def CoDisconnectContext(dwTimeout):
    CoDisconnectContext = ole32.CoDisconnectContext
    res = CoDisconnectContext(dwTimeout)
    if res != S_OK:
        raise WinError(res)
    

def CoGetCallContext(riid, ppInterface):
    CoGetCallContext = ole32.CoGetCallContext
    res = CoGetCallContext(riid, ppInterface)
    if res != S_OK:
        raise WinError(res)
    

def CoQueryProxyBlanket(pProxy, 
                        pwAuthnSvc, 
                        pAuthzSvc, 
                        pServerPrincName, 
                        pAuthnLevel, 
                        pImpLevel, 
                        pAuthInfo, 
                        pCapabilites):
    
    CoQueryProxyBlanket = ole32.CoQueryProxyBlanket
    res = CoQueryProxyBlanket(pProxy, 
                              pwAuthnSvc, 
                              pAuthzSvc, 
                              pServerPrincName, 
                              pAuthnLevel, 
                              pImpLevel, 
                              pAuthInfo, 
                              pCapabilites
    )

    if res != S_OK:
        raise WinError(res)
    

def CoSetProxyBlanket(pProxy, 
                      dwAuthnSvc, 
                      dwAuthzSvc, 
                      pServerPrincName, 
                      dwAuthnLevel, 
                      dwImpLevel, 
                      pAuthInfo, 
                      dwCapabilities):
    
    CoSetProxyBlanket = ole32.CoSetProxyBlanket
    res = CoSetProxyBlanket(pProxy, 
                            dwAuthnSvc, 
                            dwAuthzSvc, 
                            pServerPrincName, 
                            dwAuthnLevel, 
                            dwImpLevel, 
                            pAuthInfo, 
                            dwCapabilities
    )

    if res != S_OK:
        raise WinError(res)
    

def CoCopyProxy(pProxy, ppCopy):
    CoCopyProxy = ole32.CoCopyProxy
    res = CoCopyProxy(pProxy, ppCopy)
    if res != S_OK:
        raise WinError(res)
    

def CoQueryClientBlanket(pAuthnSvc, 
                         pAuthzSvc, 
                         pServerPrincName, 
                         pAuthnLevel, 
                         pImpLevel, 
                         pPrivs, 
                         pCapabilities):
    
    CoQueryClientBlanket = ole32.CoQueryClientBlanket
    res = CoQueryClientBlanket(pAuthnSvc, 
                               pAuthzSvc, 
                               pServerPrincName, 
                               pAuthnLevel, 
                               pImpLevel, 
                               pPrivs, 
                               pCapabilities
    )

    if res != S_OK:
        raise WinError(res)
    

def CoImpersonateClient():
    CoImpersonateClient = ole32.CoImpersonateClient
    res = CoImpersonateClient()
    return res


def CoRevertToSelf():
    CoRevertToSelf = ole32.CoRevertToSelf
    res = CoRevertToSelf()
    return res


def CoQueryAuthenticationServices(pcAuthSvc, asAuthSvc):
    CoQueryAuthenticationServices = ole32.CoQueryAuthenticationServices
    res = CoQueryAuthenticationServices(pcAuthSvc, asAuthSvc)
    if res != S_OK:
        raise WinError(res)
    

def CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv):
    CoCreateInstance = ole32.CoCreateInstance
    res = CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv)
    if res != S_OK:
        raise WinError(res)
    

def CoCreateInstanceEx(Clsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults):
    CoCreateInstanceEx = ole32.CoCreateInstanceEx
    res = CoCreateInstanceEx(Clsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults)
    if res != S_OK:
        raise WinError(res)
    

def CoGetCancelObject(dwThreadId, iid, ppUnk):
    CoGetCancelObject = ole32.CoGetCancelObject
    res = CoGetCancelObject(dwThreadId, iid, ppUnk)
    if res != S_OK:
        raise WinError(res)
    

def CoSetCancelObject(pUnk):
    CoSetCancelObject = ole32.CoSetCancelObject
    res = CoSetCancelObject(pUnk)
    if res != S_OK:
        raise WinError(res)
    

def CoCancelCall(dwThreadId, ulTimeout):
    CoCancelCall = ole32.CoCancelCall
    res = CoCancelCall(dwThreadId, ulTimeout)
    if res != S_OK:
        raise WinError(res)
    

def CoTestCancel():
    CoTestCancel = ole32.CoTestCancel
    res = CoTestCancel()
    return res


def CoEnableCallCancellation(pReserved):
    CoEnableCallCancellation = ole32.CoEnableCallCancellation
    res = CoEnableCallCancellation(pReserved)
    if res != S_OK:
        raise WinError(res)
    

def CoDisableCallCancellation(pReserved):
    CoDisableCallCancellation = ole32.CoDisableCallCancellation
    res = CoDisableCallCancellation(pReserved)
    if res != S_OK:
        raise WinError(res)
    

def StringFromCLSID(rclsid: Any, lplpsz: Any) -> None:
    StringFromCLSID = ole32.StringFromCLSID
    res = StringFromCLSID(rclsid, lplpsz)
    if res != S_OK:
        raise WinError(res)


def CLSIDFromString(lpsz: str, pclsid: Any) -> None:
    CLSIDFromString = ole32.CLSIDFromString
    res = CLSIDFromString(lpsz, pclsid)
    if res != S_OK:
        raise WinError(res)


def StringFromIID(rclsid, lplpsz):
    StringFromIID = ole32.StringFromIID
    res = StringFromIID(rclsid, lplpsz)
    if res != S_OK:
        raise WinError(res)
    

def IIDFromString(lpsz, lpiid):
    IIDFromString = ole32.IIDFromString
    res = IIDFromString(lpsz, lpiid)
    if res != S_OK:
        raise WinError(res)
    

def ProgIDFromCLSID(clsid, lplpszProgID):
    ProgIDFromCLSID = ole32.ProgIDFromCLSID
    res = ProgIDFromCLSID(clsid, lplpszProgID)
    if res != S_OK:
        raise WinError(res)
    

def CLSIDFromProgID(lpszProgID, lpclsid):
    CLSIDFromProgID = ole32.CLSIDFromProgID
    res = CLSIDFromProgID(lpszProgID, lpclsid)
    if res != S_OK:
        raise WinError(res)
    

def StringFromGUID2(rguid: Any, lpsz: Any, cchMax: int) -> None:
    StringFromGUID2 = ole32.StringFromGUID2
    res = StringFromGUID2(rguid, lpsz, cchMax)
    if not res:
        raise WinError(res)
    

def CoCreateGuid(pguid):
    CoCreateGuid = ole32.CoCreateGuid
    res = CoCreateGuid(pguid)
    if res != S_OK:
        raise WinError(res)
    

class tagPROPVARIANT(Structure):
    pass

PROPVARIANT = tagPROPVARIANT


def PropVariantCopy(pvarDest, pvarSrc):
    PropVariantCopy = ole32.PropVariantCopy
    res = PropVariantCopy(pvarDest, pvarSrc)
    if res != S_OK:
        raise WinError(res)
    

def PropVariantClear(pvar):
    PropVariantClear = ole32.PropVariantClear
    res = PropVariantClear(pvar)
    if res != S_OK:
        raise WinError(res)
    

def FreePropVariantArray(cVariants, rgvars):
    FreePropVariantArray = ole32.FreePropVariantArray
    res = FreePropVariantArray(cVariants, rgvars)
    if res != S_OK:
        raise WinError(res)
    

def CoWaitForMultipleHandles(dwFlags, dwTimeout, cHandles, pHandles, lpdwindex):
    CoWaitForMultipleHandles = ole32.CoWaitForMultipleHandles
    res = CoWaitForMultipleHandles(dwFlags, dwTimeout, cHandles, pHandles, lpdwindex)
    if res != S_OK:
        raise WinError(res)
    

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


def CoGetTreatAsClass(clsidOld, pClsidNew):
    CoGetTreatAsClass = ole32.CoGetTreatAsClass
    res = CoGetTreatAsClass(clsidOld, pClsidNew)
    if res != S_OK:
        raise WinError(res)
    

def CoInvalidateRemoteMachineBindings(pszMachineName):
    CoInvalidateRemoteMachineBindings = ole32.CoInvalidateRemoteMachineBindings
    res = CoInvalidateRemoteMachineBindings(pszMachineName)
    if res != S_OK:
        raise WinError(res)
    

def DllGetClassObject(rclsid, riid, ppv):
    DllGetClassObject = ole32.DllGetClassObject
    res = DllGetClassObject(rclsid, riid, ppv)
    if res != S_OK:
        raise WinError(res)
    

def DllCanUnloadNow():
    DllCanUnloadNow = ole32.DllCanUnloadNow
    res = DllCanUnloadNow()
    return res


def CoTaskMemAlloc(cb):
    CoTaskMemAlloc = ole32.CoTaskMemAlloc
    res = CoTaskMemAlloc(cb)
    if res == NULL:
        raise WinError(GetLastError())
    return res
    

def CoTaskMemRealloc(pv, cb):
    CoTaskMemRealloc = ole32.CoTaskMemRealloc
    res = CoTaskMemRealloc(pv, cb)
    if res == NULL:
        raise WinError(GetLastError())
    return res


def CoTaskMemFree(pv):
    CoTaskMemFree = ole32.CoTaskMemFree
    CoTaskMemFree(pv)