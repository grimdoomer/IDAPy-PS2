"""
    LabelExecutableSyscalls.py:
        Python script for IDA to help label syscalls in a PS2 EE executable (non-kernel)
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
    

def main():

    syscallsFound = 0

    # Loop through all the segments and scan any marked as code.
    seg = ida_segment.get_first_seg()
    while True:
    
        print("Scanning %s" % ida_segment.get_segm_name(seg))
        
        # Search the segment for syscall instructions.
        syscallAddr = FindBytes(seg.startEA, seg.endEA, [ 0x0C, 0x00, 0x00, 0x00 ])
        while syscallAddr != idaapi.BADADDR:
        
            # Make sure the data is instruction-aligned.
            if syscallAddr % 4 != 0:
                
                # Find next instance.
                syscallAddr = FindBytes(syscallAddr + 1, seg.endEA, [ 0x0C, 0x00, 0x00, 0x00 ])
                continue
        
            print("Found at 0x%08x" % syscallAddr)
        
            # Search a max of 4 instructions back for the syscall ordinal.
            for i in range(1, 5):
            
                # Disassemble the instruction.
                insSize = idaapi.decode_insn(syscallAddr - (i * 4))
                ins = idaapi.cmd
                if ins.get_canon_mnem() != "li":
                    continue
                    
                # Check if this is register $v1 and get the syscall ordinal.
                if ins.Operands[0].reg != 3:
                    continue
                    
                # Get the syscall ordinal and check if we have a name for it.
                ordinal = ins.Operands[1].value
                if ordinal >=0 and ordinal < len(Ps2Kernel.SYSCALL_TABLE) and len(Ps2Kernel.SYSCALL_TABLE[ordinal]) > 0:
                
                    # Get the function size and check if it's a stub or not.
                    func = ida_funcs.get_func(syscallAddr)
                    if func is not None and (func.endEA - func.startEA) / 4 == 4:
                    
                        # Label the function.
                        print("Found '%s' at 0x%08x" % (Ps2Kernel.SYSCALL_TABLE[ordinal], func.startEA))
                        ida_name.set_name(func.startEA, Ps2Kernel.SYSCALL_TABLE[ordinal], ida_name.SN_NON_PUBLIC | ida_name.SN_FORCE)
                        syscallsFound += 1
                        break
                        
            # Find next instance.
            syscallAddr = FindBytes(syscallAddr + 4, seg.endEA, [ 0x0C, 0x00, 0x00, 0x00 ])
            
        # Next segment.
        seg = ida_segment.get_next_seg(seg.startEA)
        if seg is None:
            break
            
    print("Found %d syscall stub functions" % syscallsFound)
    
    
main()
