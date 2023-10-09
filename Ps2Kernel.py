"""
    Ps2Kernel.py
        Contains definitions for PS2 kernel data, used by other python scripts
"""

from idaapi import *
from idautils import *
from idc import *
from collections import namedtuple

ExceptionHandlerInfo = namedtuple('ExceptionHandlerInfo', ['address', 'name'])

def Ps2KernelInit():

    global EXCEPTION_HANLDERS
    global SYSCALL_TABLE

    EXCEPTION_HANLDERS = [
        ExceptionHandlerInfo(0x80000280, 'v_Syscall'),
    ]

    SYSCALL_TABLE = [
        "",
        "ResetEE",                  # 1
        "SetGsCrt",                 # 2
        "",
        "Exit",                     # 4
        "_ResumeIntrDispatch",      # 5
        "LoadExecPS2",              # 6
        "ExecPS2",                  # 7
        "_ResumeT3IntrDispatch",    # 8
        "",
        "AddSbusIntcHandler",       # 0xA
        "RemoveSbusIntcHandler",    # 0xB
        "Interrupt2Iop",            # 0xC
        "SetVTLBRefillHandler",     # 0xD
        "SetVCommonHandler",        # 0xE
        "SetVInterruptHandler",     # 0xF
        "AddIntcHandler",           # 0x10
        "RemoveIntcHandler",        # 0x11
        "AddDmacHandler",           # 0x12
        "RemoveDmacHandler",        # 0x13
        "_EnableIntc",              # 0x14
        "_DisableIntc",             # 0x15
        "_EnableDmac",              # 0x16
        "_DisableDmac",             # 0x17
        "_SetAlarm",                # 0x18
        "_ReleaseAlarm",            # 0x19
        "_iEnableIntc",             # 0x1A
        "_iDisableIntc",            # 0x1B
        "_iEnableDmac",             # 0x1C
        "_iDisableDmac",            # 0x1D
        "_iSetAlarm",               # 0x1E
        "_iReleaseAlarm",           # 0x1F
        "CreateThread",             # 0x20
        "DeleteThread",             # 0x21
        "StartThread",              # 0x22
        "ExitThread",               # 0x23
        "ExitDeleteThread",         # 0x24
        "TerminateThread",          # 0x25
        "iTerminateThread",         # 0x26
        "DisableDispatchThread",    # 0x27
        "EnableDispatchThread",     # 0x28
        "ChangeThreadPriority",     # 0x29
        "iChangeThreadPriority",    # 0x2A
        "RotateThreadReadyQueue",   # 0x2B
        "_iRotateThreadReadyQueue", # 0x2C
        "ReleaseWaitThread",        # 0x2D
        "iReleaseWaitThread",       # 0x2E
        "GetThreadId",              # 0x2F
        "ReferThreadStatus",        # 0x30
        "iReferThreadStatus",       # 0x31
        "SleepThread",              # 0x32
        "WakeupThread",             # 0x33
        "iWakeupThread",            # 0x34
        "CancelWakeupThread",       # 0x35
        "iCancelWakeupThread",      # 0x36
        "SuspendThread",            # 0x37
        "iSuspendThread",           # 0x38
        "ResumeThread",             # 0x39
        "iResumeThread",            # 0x3A
        "JoinThread",               # 0x3B
        "InitMainThread",           # 0x3C
        "InitHeap",                 # 0x3D
        "EndOfHeap",                # 0x3E
        "",
        "CreateSema",               # 0x40
        "DeleteSema",               # 0x41
        "SignalSema",               # 0x42
        "iSignalSema",              # 0x43
        "WaitSema",                 # 0x44
        "PollSema",                 # 0x45
        "iPollSema",                # 0x46
        "ReferSemaStatus",          # 0x47
        "iReferSemaStatus",         # 0x48
        "iDeleteSema",              # 0x49
        "SetOsdConfigParam",        # 0x4A
        "GetOsdConfigParam",        # 0x4B
        "GetGsHParam",              # 0x4C
        "GetGsVParam",              # 0x4D
        "SetGsHParam",              # 0x4E
        "SetGsVParam",              # 0x4F
        "CreateEventFlag",          # 0x50
        "DeleteEventFlag",          # 0x51
        "SetEventFlag",             # 0x52
        "iSetEventFlag",            # 0x53
        "xlaunch",                  # 0x54
        "PutTLBEntry",              # 0x55
        "SetTLBEntry",              # 0x56
        "GetTLBEntry",              # 0x57
        "ProbeTLBEntry",            # 0x58
        "ExpandScratchPad",         # 0x59
        "Copy",                     # 0x5A
        "GetEntryAddress",          # 0x5B
        "EnableIntcHandler",        # 0x5C
        "DisableIntcHandler",       # 0x5D
        "EnableDmacHandler",        # 0x5E
        "DisableDmacHandler",       # 0x5F
        "KSeg0",                    # 0x60
        "EnableCache",              # 0x61
        "DisableCache",             # 0x62
        "GetCop0",                  # 0x63
        "FlushCache",               # 0x64
        "",
        "CpuConfig",                # 0x66
        "iGetCop0",                 # 0x67
        "iFlushCache",              # 0x68
        "",
        "iCpuConfig",               # 0x6A
        "SifStopDma",               # 0x6B
        "SetCPUTimerHandler",       # 0x6C
        "SetCPUTimer",              # 0x6D
        "SetOsdConfigParam2",       # 0x6E
        "GetOsdConfigParam2",       # 0x6F
        "GsGetIMR",                 # 0x70
        "GsPutIMR",                 # 0x71
        "SetPgifHandler",           # 0x72
        "SetVSyncFlag",             # 0x73
        "SetSyscall",               # 0x74
        "_print",                   # 0x75
        "SifDmaStat",               # 0x76
        "SifSetDma",                # 0x77
        "SifSetDChain",             # 0x78
        "SifSetReg",                # 0x79
        "SifGetReg",                # 0x7A
        "ExecOSD",                  # 0x7B
        "Deci2Call",                # 0x7C
        "PSMode",                   # 0x7D
        "MachineType",              # 0x7E
        "GetMemorySize",            # 0x7F
        "_GetGsDxDyOffset",         # 0x80
        "",
        "_InitTLB",                 # 0x82
        "FindAddress",              # 0x83
        "",
        "SetMemoryMode",            # 0x84
        "",
        "ExecPSX"                   # 0x86
    ]
    
    
# Init module
Ps2KernelInit()