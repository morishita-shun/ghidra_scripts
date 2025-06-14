# Recover ARM syscall function.
# @author Shun Morishita
# @category Symbol
# @runtime PyGhidra

import system_calls
import __main__ as ghidra_app
from ghidra.program.model.address import AddressSet
from ghidra.program.model.block import IsolatedEntrySubModel
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor


ARCH_ARM_LE = "ARM:LE:32:v8"
LANGS = [ARCH_ARM_LE]
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


def recoverArmSyscallFunc(listing, func):
    # reverse order
    instructs = listing.getInstructions(func.getBody(), False)
    syscall_names = []
    while instructs.hasNext():
        # ; mov r7, #0x37 ; swi 0x0
        # ; ldr r7, [DAT_0001390c] ; swi 0x0
        instruct = instructs.next()
        if not instruct:
            continue
        if instruct.getNumOperands() != 1:
            continue
        mnemonic = instruct.getMnemonicString()
        first_operand = instruct.getDefaultOperandRepresentation(0)
        if mnemonic != "swi":
            continue
        if int(first_operand, 0) != 0:
            continue
        if not instructs.hasNext():
            break
        # get next instruction
        instruct = instructs.next()
        if instruct.getNumOperands() != 2:
            continue
        first_operand = instruct.getDefaultOperandRepresentation(0)
        if first_operand != "r7":
            continue
        second_operand = instruct.getDefaultOperandRepresentation(1)
        syscall_number = getIntNumber(second_operand)
        if not syscall_number:
            continue
        syscall_name = getArmSyscallName(syscall_number)
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
        setFunctionName(func, new_func_name)
    return None


def getArmSyscallName(syscall_number):
    # ref. https://github.com/hrw/syscalls-table/blob/master/bin/syscall#L36
    syscall_arch = "arm"
    for syscall_name in SYSCALLS.names():
        try:
            if syscall_number == SYSCALLS.get(syscall_name, syscall_arch):
                return syscall_name
        except system_calls.NotSupportedSystemCall:
            pass
    return None


def getIntNumber(operand):
    if "#" in operand:
        # "#0x37"
        return int(operand.strip("#"), 16)
    elif "[" in operand:
        # "[0x1390c]"
        data_addr = toAddr(operand.strip("[]"))
        return getInt(data_addr)
    return None


def setFunctionName(func, name):
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
    language_id = currentProgram.getLanguageID().toString()
    if language_id not in LANGS:
        print("error: this script only target for " + str(LANGS))
    listing = currentProgram.getListing()
    func_mgr = currentProgram.getFunctionManager()
    monitor = ConsoleTaskMonitor()
    defUndefinedFuncs(listing, monitor)
    # recover function name
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        recoverArmSyscallFunc(listing, func)
