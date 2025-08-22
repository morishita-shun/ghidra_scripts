# Recover syscall function.
# @author Shun Morishita
# @category Symbol
# @menupath Tools.Recover syscall function
# @toolbar
# @runtime PyGhidra

import system_calls
import __main__ as ghidra_app
from ghidra.program.model.address import AddressSet
from ghidra.program.model.block import IsolatedEntrySubModel
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor


ARCH_ARM_LE = "ARM:LE:32:v8"
ARCH_M68K = "68000:BE:32:Coldfire"
ARCH_MIPS_BE = "MIPS:BE:32:default"
ARCH_MIPS_LE = "MIPS:LE:32:default"
ARCH_PPC = "PowerPC:BE:32:default"
ARCH_X86 = "x86:LE:32:default"
ARCH_X86_64 = "x86:LE:64:default"
LANGS = [ARCH_ARM_LE, ARCH_M68K, ARCH_MIPS_BE, ARCH_MIPS_LE, ARCH_PPC, ARCH_X86, ARCH_X86_64]
LANGUAGE_ID = currentProgram.getLanguageID().toString()
SYSCALLS = system_calls.syscalls()


def defUndefinedFuncs(listing, monitor):
    # ref. https://github.com/EliasKotlyar/Med9GhidraScripts/blob/main/general/DefineUndefinedFunctions.py
    addr_set = AddressSet()
    instructs = listing.getInstructions(currentProgram.getMemory(), True)
    while instructs.hasNext() and not monitor.isCancelled():
        instruct = instructs.next()
        addr_set.addRange(instruct.getMinAddress(), instruct.getMaxAddress())
    funcs = listing.getFunctions(True)
    while funcs.hasNext() and not monitor.isCancelled():
        func = funcs.next()
        addr_set.delete(func.getBody())
    if addr_set.getNumAddressRanges() == 0:
        return None
    # go through address set and find actual start of flow into dead code
    submodel = IsolatedEntrySubModel(currentProgram)
    subIter = submodel.getCodeBlocksContaining(addr_set, monitor)
    codeStarts = AddressSet()
    # sometimes IsolatedEntrySubModel() doesnt work correctly, we set the maximum value to 1000
    i = 0
    while subIter.hasNext():
        if i >= 1000:
            return None
        block = subIter.next()
        deadStart = block.getFirstStartAddress()
        codeStarts.add(deadStart)
        i += 1
    for startAdr in codeStarts:
        phyAdr = startAdr.getMinAddress()
        createFunction(phyAdr, None)
    return None


def recoverSyscallFunc(listing, func):
    # reverse order
    instructs = listing.getInstructions(func.getBody(), False)
    syscall_names = []
    # arm: mov r7, #0x37 ; swi 0x0
    # arm: ldr r7, [DAT_0001390c] ; swi 0x0
    # m68k: moveq # 0x6, D0 ; trap # 0x0
    # mips: li v0, 0xfa5 ; syscall
    # ppc: li r0, 0x6 ; sc 0x0
    # x86: MOV EAX, 0xa ; INT 0x80
    # x86_64: MOV EAX, 0x57 ; SYSCALL
    # dont handle sh4 and sparc, because the assignment instruction may not be next
    while instructs.hasNext():
        instruct = instructs.next()
        if not instruct:
            continue
        # check syscall instruct
        if LANGUAGE_ID in [ARCH_MIPS_BE, ARCH_MIPS_LE, ARCH_X86_64]:
            if instruct.getNumOperands() != 0:
                continue
        elif LANGUAGE_ID in [ARCH_ARM_LE, ARCH_M68K, ARCH_PPC, ARCH_X86]:
            if instruct.getNumOperands() != 1:
                continue
            first_operand = instruct.getDefaultOperandRepresentation(0)
        mnemonic = instruct.getMnemonicString()
        if LANGUAGE_ID == ARCH_ARM_LE:
            if mnemonic != "swi":
                continue
            if getIntNumber(first_operand) != 0x0:
                continue
        elif LANGUAGE_ID == ARCH_M68K:
            if mnemonic != "trap":
                continue
            if getIntNumber(first_operand) != 0x0:
                continue
        elif LANGUAGE_ID in [ARCH_MIPS_BE, ARCH_MIPS_LE]:
            if mnemonic != "syscall":
                continue
        elif LANGUAGE_ID == ARCH_PPC:
            if mnemonic != "sc":
                continue
            if getIntNumber(first_operand) != 0x0:
                continue
        elif LANGUAGE_ID == ARCH_X86:
            if mnemonic != "INT":
                continue
            if getIntNumber(first_operand) != 0x80:
                continue
        elif LANGUAGE_ID == ARCH_X86_64:
            if mnemonic != "SYSCALL":
                continue
        if not instructs.hasNext():
            break
        instruct = instructs.next()
        # check assignment instruct
        if instruct.getNumOperands() != 2:
            continue
        first_operand = instruct.getDefaultOperandRepresentation(0)
        second_operand = instruct.getDefaultOperandRepresentation(1)
        if LANGUAGE_ID == ARCH_ARM_LE:
            if first_operand != "r7":
                continue
        elif LANGUAGE_ID == ARCH_M68K:
            if second_operand != "D0":
                continue
        elif LANGUAGE_ID in [ARCH_MIPS_BE, ARCH_MIPS_LE]:
            if first_operand != "v0":
                continue
        elif LANGUAGE_ID == ARCH_PPC:
            if first_operand != "r0":
                continue
        elif LANGUAGE_ID == ARCH_X86:
            if first_operand != "EAX":
                continue
        elif LANGUAGE_ID == ARCH_X86_64:
            if first_operand not in ("EAX", "RAX"):
                continue
        if LANGUAGE_ID == ARCH_M68K:
            syscall_number = getIntNumber(first_operand)
        else:
            syscall_number = getIntNumber(second_operand)
        if not syscall_number:
            continue
        syscall_name = getSyscallName(syscall_number)
        if not syscall_name:
            continue
        syscall_names.append(syscall_name)
        # add comment
        if not getPostComment(instruct.getAddress()):
            setPostComment(instruct.getAddress(), str(syscall_number) + ": " + syscall_name)
    if syscall_names:
        syscall_names = list(set(syscall_names))
        new_func_name = "_".join(syscall_names)
        new_func_name += "_" + func.getEntryPoint().toString()
        #print(func.getName() + " -> " + new_func_name)
        setFuncName(func, new_func_name)
    return None


def getSyscallName(syscall_number):
    # ref. https://github.com/hrw/syscalls-table/blob/master/bin/syscall#L36
    if LANGUAGE_ID == ARCH_ARM_LE:
        syscall_arch = "arm"
    elif LANGUAGE_ID == ARCH_M68K:
        syscall_arch = "m68k"
    elif LANGUAGE_ID in [ARCH_MIPS_BE, ARCH_MIPS_LE]:
        syscall_arch = "mipso32"
    elif LANGUAGE_ID == ARCH_PPC:
        syscall_arch = "powerpc"
    elif LANGUAGE_ID == ARCH_X86:
        syscall_arch = "i386"
    elif LANGUAGE_ID == ARCH_X86_64:
        syscall_arch = "x86_64"
    for syscall_name in SYSCALLS.names():
        try:
            if syscall_number == SYSCALLS.get(syscall_name, syscall_arch):
                return syscall_name
        except system_calls.NotSupportedSystemCall:
            pass
    return None


def setSyscallFuncName(func, syscall_names):
    if syscall_names:
        syscall_names = list(set(syscall_names))
        new_func_name = "_".join(syscall_names)
        new_func_name += "_" + func.getEntryPoint().toString()
        #print(func.getName() + " -> " + new_func_name)
        setFuncName(func, new_func_name)
    return None


def getIntNumber(operand):
    try:
        if "#" in operand:
            # "#0x37"
            return int(operand.strip("#"), 16)
        elif "[" in operand:
            # "[0x1390c]"
            data_addr = toAddr(operand.strip("[]"))
            return getInt(data_addr)
        elif "0x" in operand:
            # "0xfa5"
            return int(operand, 0)
    except:
        return None
    return None


def setFuncName(func, name):
    if not func:
        return None
    original_func_name = func.getName()
    if not original_func_name.startswith("FUN_"):
        return None
    #func_name = name + "_" + func.getEntryPoint().toString()
    func_name = name
    func.setName(func_name, SourceType.USER_DEFINED)
    print("recover: " + original_func_name + " -> " + func_name)
    return None


if __name__ == "__main__":
    if LANGUAGE_ID not in LANGS:
        print("error: this script only target for " + str(LANGS))
    listing = currentProgram.getListing()
    func_mgr = currentProgram.getFunctionManager()
    monitor = ConsoleTaskMonitor()
    defUndefinedFuncs(listing, monitor)
    # recover function name
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        recoverSyscallFunc(listing, func)
