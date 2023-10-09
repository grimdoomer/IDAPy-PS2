"""
    LabelKernelSyscalls.py:
        Python script for IDA to help label syscalls in a PS2 EE kernel image
"""

from idaapi import *
from idautils import *
from idc import *
import Ps2Kernel

def FindBytes(startEA, endEA, data):

    # Roll our own find bytes api because IDA's is too complicated (shocker).
    
    if endEA - len(data) < startEA:
        return idaapi.BADADDR
    
    # Loop and find the next instance of the search pattern.
    for i in range(startEA, endEA - len(data)):
    
        # Check for the search pattern.
        found = True
        for x in range(len(data)):
            if idc.Byte(i + x) != data[x]:
                found = False
                break
                
        # Check if the data matches.
        if found == True:
            return i
            
    # If we made it here we did not find the data.
    return idaapi.BADADDR
    

def LabelExceptionHandlers():

    # Loop and label exception handlers.
    for i in range(len(Ps2Kernel.EXCEPTION_HANLDERS)):
    
        # Create the exception handler function and label it.
        ida_funcs.add_func(Ps2Kernel.EXCEPTION_HANLDERS[i].address, idaapi.BADADDR)
        ida_name.set_name(Ps2Kernel.EXCEPTION_HANLDERS[i].address, Ps2Kernel.EXCEPTION_HANLDERS[i].name, ida_name.SN_NON_PUBLIC | ida_name.SN_FORCE)
        

def LabelSyscallTable():

    syscallCount = 0
    syscallTableAddress = 0

    # Search for 'li $k0, N' = N 00 1A 24
    findAddr = FindBytes(0x80000280, 0x80000380, [ 0x00, 0x1A, 0x24 ])
    if findAddr == idaapi.BADADDR:
    
        # Error while finding syscall count.
        print("Failed to find syscall count!")
        return
        
    # Get the number of syscalls.
    syscallCount = idc.Byte(findAddr - 1)
    
    # The syscall table address is loaded from the following instructions:
    #   01 80 1A 3C    lui  $k0, 0x8001
    #   21 D0 43 03    addu $k0, $k0, $v1
    #   00 4D 5A 8F    lw   $k0, 0x4d00($k0)
    findAddr = FindBytes(findAddr + 3, 0x80000380, [ 0x1A, 0x3C, 0x21, 0xD0, 0x43, 0x03 ])
    if findAddr == idaapi.BADADDR:
    
        # Error while finding syscall table address.
        print("Failed to find syscall table address!")
        return
        
    # Get the syscall table address.
    syscallTableAddress = (idc.Word(findAddr - 2) << 16) | idc.Word(findAddr + 6)
    idc.MakeNameEx(syscallTableAddress, "_SyscallTable", idc.SN_NON_PUBLIC)
    print("Syscall table found at 0x%08x %d" % (syscallTableAddress, syscallCount))

    # Get the function pointer for the disabled stub.
    disabledStub = idc.Dword(syscallTableAddress)
    ida_name.set_name(disabledStub, "undefined_syscall", ida_name.SN_NON_PUBLIC)

    # Loop and label syscalls.
    count = 1
    for i in range(syscallTableAddress + 4, syscallTableAddress + (syscallCount * 4), 4):
        
        idc.MakeDword(i)
        funcPtr = idc.Dword(i)
        
        # Create the function and let the auto analyzer do the work.
        ida_funcs.add_func(funcPtr)
        
        # Check if the function is disabled or if we have a name for it.
        if funcPtr == disabledStub:
        
            # Check if we have a name for the function.
            if count < len(Ps2Kernel.SYSCALL_TABLE) and len(Ps2Kernel.SYSCALL_TABLE[count]) > 0:
                idc.MakeComm(i, "syscall %x (disabled) %s" % (count, Ps2Kernel.SYSCALL_TABLE[count]))
            else:
                idc.MakeComm(i, "syscall %x (disabled)" % count)
            
        elif count < len(Ps2Kernel.SYSCALL_TABLE):
        
            if len(Ps2Kernel.SYSCALL_TABLE[count]) > 0:
                ida_name.set_name(funcPtr, Ps2Kernel.SYSCALL_TABLE[count], ida_name.SN_NON_PUBLIC)
            else:
                ida_name.set_name(funcPtr, "syscall_%d" % count, ida_name.SN_NON_PUBLIC)
                
            idc.MakeComm(i, "syscall %x" % count)
        
        count += 1


def main():

    # Label exception handlers.
    LabelExceptionHandlers()
    
    # Find and label syscall table.
    LabelSyscallTable()
    
    
main()