# coding = 'utf-8'

import math
import warnings
import subprocess
from device_method.sys_win import *
from device_method.windows import *
from device_method.messagebox import *
from device_method.TaskDialogIndirect import *

# messagebox

print(MessageBox(HWND(), 'abc', 'abc', MB_ICONINFORMATION)) 
print(MessageBoxEx(HWND(), 'hello world', 'News', MB_ICONINFORMATION))
print("info", showinfo("Spam", "Egg Information"))
print("warning", showwarning("Spam", "Egg Warning"))
print("error", showerror("Spam", "Egg Alert"))
print("question", askquestion("Spam", "Question?"))
print("proceed", askokcancel("Spam", "Proceed?"))
print("yes/no", askyesno("Spam", "Got it?"))
print("yes/no/cancel", askyesnocancel("Spam", "Want it?"))
print("try again", askretrycancel("Spam", "Try again?"))
print(MessageBoxIndirect(lpCaption='News', lpszText='Hello World!', dwStyle=MB_OKCANCEL | MB_ICONINFORMATION))

# TaskDialogIndirect

print(TaskDialog(pszWindowTitle='News', 
                     pszMainInstruction='Hello World!', 
                     pszContent='Welcome to Python!', 
                     pszIcon=TD_INFORMATION_ICON, 
                     dwCommonButtons=TDCBF_OK_BUTTON)
)
    
print(TaskDialogIndirect(pszWindowTitle= 'News', 
                            pszMainInstruction='Hello World!', 
                            pszContent='Welcome to Python!', 
                            pszMainIcon=TD_INFORMATION_ICON, 
                            Buttons=[TASKDIALOG_BUTTON(100, '确定'), TASKDIALOG_BUTTON(101, '取消')],      
                            dwCommonButtons=TDCBF_RETRY_BUTTON,      
                            RadioButtons=[TASKDIALOG_BUTTON(2000, '选项1'), TASKDIALOG_BUTTON(2001, '选项2')], 
                            pszVerificationText='I agree.')
)

# ......

def cmd(admin = False, hwnd = None, nShow = SW_NORMAL) -> None:
    try:
        if admin: RunAsAdmin(nShow=nShow, hwnd=hwnd)
        subprocess.run(['cmd.exe'], shell=True, check=True)
    except OSError:
        pass


def PowerShell(admin = False, hwnd = None, nShow = SW_NORMAL) -> None:
    try:
        if admin: RunAsAdmin(nShow=nShow, hwnd=hwnd)
        subprocess.run(['powershell.exe'], shell=True, check=True)
    except OSError:
        pass


def Run():
    # Run CLSID: {2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}
    ShellExecute(lpFile='shell:::{2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}')


def round(number, ndigits: int = None, return_str: bool = False):
    '''
    ~~The method has been deprecated~~
    ~~（此方法已弃用）~~

    Round a number to a given precision in decimal digits.

    The return value is an integer if ndigits is omitted or None.   
    Ndigits not may be negative.

    （将一个数字四舍五入到指定的小数位精度。

    如果省略了 ndigits 或者 ndigits 为 None，则返回值为整数。
    ndigits 不得为负数。）
    '''

    warnings.warn('The method has been deprecated', DeprecationWarning, stacklevel=2)

    try:
        number = "".join(str(float(number)).split(' '))
    except ValueError:
        raise TypeError('The input number is not a number')
    
    if ndigits is None:
        ndigits = 0
    
    if 'nan' in number:
        return str(math.nan) if return_str else math.nan
    elif 'inf' in number:
        if number.startswith('-'):
            return number if return_str else -math.inf
        return number if return_str else math.inf
    
    if ndigits < 0:
        raise ZeroDivisionError('The value provided for the retained decimal places must not be less than zero')
    
    if str(ndigits).count('.') > 0:
        raise ZeroDivisionError('Values that retain decimal places must be integers, they cannot be decimals')
    
    if 'e' in number:
        total = number.split('e')
        main = list(total[0])
        index = total[1]
        if float(index) >= 0:
            return str(float(number)) if return_str else float(number)
        
        if '.' in main:
            main.remove('.')
        for op in range(1, abs(int(float(index)))):
            main.insert(0, '0')
        main = "".join(main)
        number = f'0.{main}'

    number = number.split('.')
    integer = number[0]
    fractional = list(number[1])

    for i in range(0, ndigits + 6):
        fractional.append('0')
    
    num = 0
    new_fractional = []

    if ndigits == 0:
        if float(fractional[ndigits]) >= 5:
            integer = str(int(float(integer))+1)
        new_fractional.append('0')
    else:
        a = float(fractional[ndigits])
        if a < 5:
            while num < ndigits:
                new_fractional.append(fractional[num])
                num += 1
        else:
            while num < ndigits:
                if num == ndigits - 1:
                    new_fractional.append(str(int(float(fractional[num])+1)))
                    break
                new_fractional.append(fractional[num])
                num += 1
            
            if float(fractional[num]) == 9:
                new_fractional[num] = '0'
                while num > 0:
                    if float(new_fractional[num-1]) == 9:
                        new_fractional[num-1] = '0'
                    else:
                        break
                    num -= 1

                if num == 0:
                    integer = str(int(float(integer) + 1))
                else:
                    new_fractional[num-1] = str(int(float(new_fractional[num-1])) + 1)
    new_fractional = "".join(new_fractional)
    result = float(f'{integer}.{new_fractional}') if ndigits else int(float(f'{integer}.{new_fractional}'))
    return str(result) if return_str else result


Run()
cmd(True)
PowerShell(True)