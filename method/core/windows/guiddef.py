# coding = 'utf-8'
# guiddef.h

from ctypes import POINTER, Structure, byref, sizeof

try:
    from public_dll import ntdll
    from win_cbasictypes import *
except ImportError:
    from .public_dll import ntdll
    from .win_cbasictypes import *

_LONG32 = ULONG

#################################################################
# from wchar.h

def memcmp(buffer1, buffer2, count):
    memcmp = ntdll.memcmp
    res = memcmp(buffer1, buffer2, count)
    return res


##################################################################
class _GUID(Structure):
    _fields_ = [('Data1', _LONG32),
                ('Data2', USHORT),
                ('Data3', USHORT),
                ('Data4', UCHAR * 8)
    ]

GUID = _GUID


def DEFINE_GUID(l: int,
                w1: int,
                w2: int,
                b1: int,
                b2: int,
                b3: int,
                b4: int,
                b5: int,
                b6: int,
                b7: int,
                b8: int) -> str:       # from guiddef.h
    
    l = f'{l:08x}'
    w1 = f'{w1:04x}'
    w2 = f'{w2:04x}'
    w3 = f'{b1:02x}{b2:02x}'
    w4 = f'{b3:02x}{b4:02x}{b5:02x}{b6:02x}{b7:02x}{b8:02x}'
    return ('{' + f'{l}-{w1}-{w2}-{w3}-{w4}' + '}').upper()


def DEFINE_OLEGUID(l: int, w1: int, w2: int) -> str:
    return DEFINE_GUID(l, w1, w2, 0xc0, 0, 0, 0, 0, 0, 0, 0x46)

LPGUID = POINTER(GUID)
LPCGUID = LPGUID

IID = GUID
LPIID = POINTER(IID)

CLSID = GUID
LPCLSID = POINTER(CLSID)

FMTID = GUID
LPFMTID = POINTER(FMTID)


def InlineIsEqualGUID(rguid1, rguid2) -> bool:
    return ((rguid1.Data1)[0] == (rguid2.Data1)[0] and
            (rguid1.Data1)[1] == (rguid2.Data1)[1] and
            (rguid1.Data1)[2] == (rguid2.Data1)[2] and
            (rguid1.Data1)[3] == (rguid2.Data1)[3]
    )

def IsEqualGUID(rguid1, rguid2):
    return memcmp(byref(rguid1), byref(rguid2), sizeof(GUID))

def IsEqualIID(riid1, riid2):
    return IsEqualGUID(riid1, riid2)

def IsEqualCLSID(rclsid1, rclsid2):
    return IsEqualIID(rclsid1, rclsid2)

def IsEqualFMTID(rfmtid1, rfmtid2):
    return IsEqualGUID(rfmtid1, rfmtid2)
