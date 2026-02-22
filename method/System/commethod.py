# coding = 'utf - 8'

from ctypes import ArgumentError
from method.System.winusutypes import *
from method.System.errcheck import hresult_to_errcheck
from method.System.win32typing import CDataType as _CDataType

_In_ = 1
_Out_ = 2
_Other_ = 4

_SupportTypes = list[tuple[int, str, _CDataType] | tuple[str, _CDataType]] | None


def COMFUNCTYPE(
    vtbl_index: int, 
    func_name: str, 
    restype: _CDataType = HRESULT, 
    argtypes: _SupportTypes = None, 
    use_errno: bool = False,
    use_last_error: bool = False,
    iid = None,
    call_type = CFUNCTYPE
):
    
    '''
    调用 COM 组件的方法

    vtbl_index: COM 组件的索引值

    func_name: COM 组件的名称

    argtypes: 输入的类型，应为 list[tuple[int, str, _CDataType]] 当省略第一个参数时，则第一个参数默认的值为1

    call_type: 调用的类型

    剩余参数与 CFUNCTYPE 或 WINFUNCTYPE 相同
    '''
    if not argtypes:
        return call_type(
            restype, 
            use_errno=use_errno, 
            use_last_error=use_last_error
        )(vtbl_index, func_name, None, iid)
    
    _flags = []
    _argtypes = []
    for c in argtypes:
        if len(c) != 3:
            if len(c) == 2:
                if not isinstance(c[0], str):
                    raise ArgumentError(
                        f'If you choose to ignore the int value, '
                        f'then the first value in the tuple must be of type str, not {type(c[0]).__name__}, '
                        f'the following is the error location: "{c}"'
                    )
                _flags.append((_In_, c[0]))
                _argtypes.append(c[1])
                continue

            raise ArgumentError(
                f'The parameters provided must be 2 or 3 instead of {len(c)}, '
                f'the following is the error location: "{c}"'
            )
        _flags.append((c[0], c[1]))
        _argtypes.append(c[2])
    
    return call_type(
        restype,
        *_argtypes,
        use_errno=use_errno,
        use_last_error=use_last_error,
    )(vtbl_index, func_name, tuple(_flags), iid)


class ComBaseClass(Structure):
    _fields_ = [('value', VOID)]

    @property
    def value(self) -> int:
        return self.value

    @property
    def this(self):
        return cast(self.value, POINTER(self.__class__))
    
    @property
    def THIS(self):
        return self.this
