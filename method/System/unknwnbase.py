# coding = 'utf-8'

from method.System.wtypesbase import *
from method.System.winusutypes import *
from method.System.wmivirtualkey import *

_In_ = 1
_Out_ = 2


class ComBaseClass(Structure):
    _fields_ = [('value', VOID)]

    @property
    def value(self):
        return self.value

    @property
    def this(self):
        value = self.value
        this = cast(value, POINTER(self.__class__))
        return this

####################################################
# unknwnbase.h

class IUnknown(ComBaseClass):
    def QueryInterface(self, riid, ppvObject) -> int:
        QueryInterface = CALLBACK(HRESULT, REFIID, POINTER(POINTER(VOID)))
        flags = (
            (_In_, 'riid'), 
            (_In_, 'ppvObject')
        )

        QueryInterface = QueryInterface(
            IUnknown_QueryInterface_Idx,
            'QueryInterface',
            flags
        )

        res = QueryInterface(self.this, riid, ppvObject)
        return res
    

    def AddRef(self) -> int:
        flags = ()
        AddRef = CALLBACK(ULONG)
        AddRef = AddRef(
            IUnknown_AddRef_Idx,
            'AddRef',
            flags
        )

        res = AddRef(self.this)
        return res


    def Release(self) -> int:
        flags = ()
        Release = CALLBACK(ULONG)
        Release = Release(
            IUnknown_Release_Idx,
            'Release',
            flags
        )

        res = Release(self.this)
        return res
