# coding = 'utf-8'

from method.System.commethod import *
from method.System.wtypesbase import *
from method.System.winusutypes import *
from method.System.guiddef import DEFINE_GUID
from method.System.commethod import _In_, _Out_
from method.System.errcheck import com_to_errcheck

####################################################
# unknwnbase.h


def IUnknown_QueryInterface(This, riid, ppvObject, errcheck: bool = True) -> int:
    IUnknown_QueryInterface = COMFUNCTYPE(
        0, 
        'QueryInterface',
        argtypes=[
            (_In_, 'riid', REFIID),
            (_In_, 'ppvObject', POINTER(VOID))
        ]
    )

    res = IUnknown_QueryInterface(This, riid, ppvObject)
    return com_to_errcheck(res, errcheck)


def IUnknown_AddRef(This, errcheck: bool = True) -> int:
    IUnknown_AddRef = COMFUNCTYPE(1, 'AddRef')
    res = IUnknown_AddRef(This)
    return com_to_errcheck(res, errcheck)


def IUnknown_Release(This, errcheck: bool = True) -> int:
    IUnknown_Release = COMFUNCTYPE(2, 'Release')
    res = IUnknown_Release(This)
    return com_to_errcheck(res, errcheck)


IID_IUnknown = DEFINE_GUID(0x00000000, 0x0000, 0x0000, 0xc0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46)
class IUnknown(ComBaseClass):
    MIDL_INTERFACE = "00000000-0000-0000-C000-000000000046"
    def QueryInterface(self, riid, ppvObject, errcheck: bool = True): return IUnknown_QueryInterface(self.this, riid, ppvObject, errcheck)    
    def AddRef(self, errcheck: bool = True): return IUnknown_AddRef(self.this, errcheck)
    def Release(self, errcheck: bool = True): return IUnknown_Release(self.this, errcheck)

class IUnknownVtbl(IUnknown): pass


def IUnknown_QueryInterface_Proxy(This, riid, ppvObject, errcheck: bool = True): return IUnknown_QueryInterface(This, riid, ppvObject, errcheck)
def IUnknown_AddRef_Proxy(This, errcheck: bool = True): return IUnknown_AddRef(This, errcheck)
def IUnknown_Release_Proxy(This, errcheck: bool = True): return IUnknown_Release(This, errcheck)

def AsyncIUnknown_QueryInterface(This,riid,ppvObject, errcheck: bool = True): return IUnknown_QueryInterface(This, riid, ppvObject, errcheck)
def AsyncIUnknown_AddRef(This, errcheck: bool = True): return IUnknown_AddRef(This, errcheck)
def AsyncIUnknown_Release(This, errcheck: bool = True): return IUnknown_Release(This, errcheck)


def AsyncIUnknown_Begin_QueryInterface(This,riid, errcheck: bool = True) -> int:
    AsyncIUnknown_Begin_QueryInterface = COMFUNCTYPE(
        3, 
        'Begin_QueryInterface', 
        argtypes=[(_In_, 'riid', REFIID)]

    )

    res = AsyncIUnknown_Begin_QueryInterface(This, riid)
    return com_to_errcheck(res, errcheck)


def AsyncIUnknown_Finish_QueryInterface(This, ppvObject, errcheck: bool = True) -> int:
    AsyncIUnknown_Begin_QueryInterface = COMFUNCTYPE(
        4,
        'Finish_QueryInterface',
        argtypes=[(_In_, 'ppvObject', POINTER(VOID))]
    )

    res = AsyncIUnknown_Begin_QueryInterface(This, ppvObject)
    return com_to_errcheck(res, errcheck)


def AsyncIUnknown_Begin_AddRef(This, errcheck: bool = True) -> int:
    AsyncIUnknown_Begin_AddRef = COMFUNCTYPE(5, 'Begin_AddRef')
    res = AsyncIUnknown_Begin_AddRef(This)
    return com_to_errcheck(res, errcheck)


def AsyncIUnknown_Finish_AddRef(This, errcheck: bool = True) -> int:
    AsyncIUnknown_Finish_AddRef = COMFUNCTYPE(6, 'Finish_AddRef')
    res = AsyncIUnknown_Finish_AddRef(This)
    return com_to_errcheck(res, errcheck)


def AsyncIUnknown_Begin_Release(This, errcheck: bool = True) -> int:
    AsyncIUnknown_Begin_Release = COMFUNCTYPE(7, 'Begin_Release')
    res = AsyncIUnknown_Begin_Release(This)
    return com_to_errcheck(res, errcheck)


def AsyncIUnknown_Finish_Release(This, errcheck: bool = True) -> int:
    AsyncIUnknown_Finish_Release = COMFUNCTYPE(8, 'Finish_Release')
    res = AsyncIUnknown_Finish_Release(This)
    return com_to_errcheck(res, errcheck)


IID_AsyncIUnknown = DEFINE_GUID(0x000e0000, 0x0000, 0x0000, 0xc0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46)
class AsyncIUnknown(IUnknown):
    MIDL_INTERFACE = "000e0000-0000-0000-c000-000000000046"
    def Begin_QueryInterface(self, riid, errcheck: bool = True): return AsyncIUnknown_Begin_QueryInterface(self.THIS, riid, errcheck)
    def Finish_QueryInterface(self, ppvObject, errcheck: bool = True): return AsyncIUnknown_Finish_QueryInterface(self.this, ppvObject, errcheck)
    def Begin_AddRef(self, errcheck: bool = True): return AsyncIUnknown_AddRef(self.this, errcheck)
    def Finish_AddRef(self, errcheck: bool = True): return AsyncIUnknown_Finish_AddRef(self.this, errcheck)
    def Begin_Release(self, errcheck: bool = True): return AsyncIUnknown_Begin_Release(self.this, errcheck)
    def Finish_Release(self, errcheck: bool = True): return AsyncIUnknown_Finish_Release(self.this, errcheck)

class AsyncIUnknownVtbl(AsyncIUnknown): pass


def IClassFactory_QueryInterface(This,riid,ppvObject, errcheck: bool = True): return IUnknown_QueryInterface(This, riid, ppvObject, errcheck)
def IClassFactory_AddRef(This, errcheck: bool = True): return IUnknown_AddRef(This, errcheck)
def IClassFactory_Release(This, errcheck: bool = True): return IUnknown_Release(This, errcheck)
def IClassFactory_CreateInstance(This, pUnkOuter, riid, ppvObject, errcheck: bool = True) -> int:
    IClassFactory_CreateInstance = COMFUNCTYPE(
        3, 
        'CreateInstance',
        argtypes = [
            (_In_, 'pUnkOuter', POINTER(IUnknown)),
            (_In_, 'riid', REFIID),
            (_In_, 'ppvObject', POINTER(VOID))
        ]
    )

    res = IClassFactory_CreateInstance(This, pUnkOuter, riid, ppvObject)
    return com_to_errcheck(res, errcheck)


def IClassFactory_LockServer(This, fLock, errcheck: bool = True) -> int:
    IClassFactory_LockServer = COMFUNCTYPE(
        4,
        'LockServer',
        argtypes=[(_In_, 'fLock', WINBOOL)]

    )

    res = IClassFactory_LockServer(This, fLock)
    return com_to_errcheck(res, errcheck)

IID_IClassFactory = DEFINE_GUID(0x00000001, 0x0000, 0x0000, 0xc0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46)
class IClassFactory(IUnknown):
    MIDL_INTERFACE = "00000001-0000-0000-c000-000000000046"
    def CreateInstance(self, pUnkOuter, riid, ppvObject, errcheck: bool = True): return IClassFactory_CreateInstance(self.this, pUnkOuter, riid, ppvObject, errcheck)
    def LockServer(self, fLock, errcheck: bool = True): return IClassFactory_LockServer(self.this, fLock, errcheck)

class IClassFactoryVtbl(IClassFactory): pass
