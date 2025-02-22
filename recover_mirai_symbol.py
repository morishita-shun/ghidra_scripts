# Recover Mirai symbols.
# @author Shun Morishita
# @category Symbol

import collections
import re
import __main__ as ghidra_app
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.database.code import DataDB
from ghidra.program.model.address import AddressSet
from ghidra.program.model.block import IsolatedEntrySubModel
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor


KEY_NAME = "name"
KEY_VECTOR = "vector"
KEY_ENTRYPOINT = "entrypoint"

ARCH_ARM_BE = "ARM:BE:32:v8"
ARCH_ARM_LE = "ARM:LE:32:v8"
ARCH_M68K = "68000:BE:32:Coldfire"
ARCH_MIPS_BE = "MIPS:BE:32:default"
ARCH_MIPS_LE = "MIPS:LE:32:default"
ARCH_PPC = "PowerPC:BE:32:default"
ARCH_SH4 = "SuperH4:LE:32:default"
ARCH_SPC = "sparc:BE:32:default"
ARCH_X86 = "x86:LE:32:default"
ARCH_X86_64 = "x86:LE:64:default"

LANGS = [
    ARCH_ARM_BE, ARCH_ARM_LE, ARCH_M68K, ARCH_MIPS_BE,
    ARCH_MIPS_LE, ARCH_PPC, ARCH_SH4, ARCH_SPC,
    ARCH_X86, ARCH_X86_64
    ]


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


def getMainFunc(func_mgr, ifc, monitor):
    main_func = main_ccode = None
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        addr_num = func.getBody().getNumAddresses()
        if addr_num < 1000:
            continue
        ccode = getDecompileCCode(func, ifc, monitor)
        if not ccode:
            continue
        close_strs = re.findall(r".+?\(0\);.+?\(1\);.+?\(2\);", ccode.toString())
        if len(close_strs) != 1:
            continue
        c2conn_strs = re.findall(
                r"(do|while\( true \)) \{.+?if \(.+? != .+?(0xffffffff|\-1)\) \{.+?\}.+?if \(.+? == .+?(0xffffffff|\-1)\)",
                ccode.toString()
                )
        if 1 <= len(c2conn_strs) <= 2:
            main_func = func
            main_ccode = ccode
            break
    return main_func, main_ccode


def getResolveCncAddrFunc(listing, func_mgr, ifc, monitor, main_func, main_ccode):
    resolve_cnc_addr_func = cnc = None
    language_id = currentProgram.getLanguageID().toString()
    func_names = [func.getName() for func in func_mgr.getFunctions(True)]
    lines = re.findall(r"[0-9a-zA-Z|_]+? = [0-9a-zA-Z|_]+?;", main_ccode.toString())
    for line in lines:
        match = re.search(r"[0-9a-zA-Z|_]+? = ([0-9a-zA-Z|_]+?);", line)
        if not match:
            continue
        func_name = match.group(1)
        if func_name not in func_names:
            continue
        func = getGlobalFunctions(func_name)[0]
        if language_id not in (ARCH_MIPS_BE, ARCH_MIPS_LE):
            entry_point = func.getEntryPoint()
            refs = getReferencesTo(entry_point)
            cand_caller_funcs = []
            for ref in refs:
                cand_caller_func = None
                # in some cases (sh4), getFunctionContaining cannot identify function correctly
                if language_id == ARCH_SH4:
                    cand_caller_func = getFunctionBefore(ref.getFromAddress())
                else:
                    cand_caller_func = getFunctionContaining(ref.getFromAddress())
                cand_caller_funcs.append(cand_caller_func)
            cand_caller_funcs = [cc_func for cc_func in cand_caller_funcs if cc_func is not None]
            # cand_caller_funcs contain main_func (+ anti_gdb_entry)
            # in some cases (mips), ghidra doesnt handle xref correctly
            if main_func not in cand_caller_funcs:
                continue
        cnc = getCnc(listing, ifc, monitor, func)
        if cnc:
            resolve_cnc_addr_func = func
            break
    return resolve_cnc_addr_func, cnc


def getCnc(listing, ifc, monitor, resolve_cnc_addr_func):
    cnc = ""
    instructs = list(listing.getInstructions(resolve_cnc_addr_func.getBody(), True))
    for instruct in instructs:
        refs = getReferencesFrom(instruct.getAddress())
        if len(refs) == 0:
            continue
        for ref in refs:
            addr = ref.getToAddress()
            data = getDataAt(addr)
            if not isinstance(data, DataDB):
                continue
            cnc = ""
            try:
                for count in range(1024):
                    byte = getUByte(addr.add(count))
                    # null
                    if byte == 0:
                        break
                    # convert ascii printable characters
                    elif 32 <= byte <= 126:
                        cnc += chr(byte)
                    else:
                        cnc += "\\x{:02x}".format(byte)
                # check domain / ip address
                if (re.match(r"^([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$", cnc) or
                        re.match(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$", cnc)):
                    break
                else:
                    cnc = ""
            except:
                pass
        if cnc:
            break
    if cnc:
        return cnc
    # parse 4 bytes to ip address
    ccode = getDecompileCCode(resolve_cnc_addr_func, ifc, monitor)
    if not ccode:
        return ""
    # ; srv_addr._4_4_ = 0xc229a6bc;
    # ; srv_addr._4_4_ = htonl(0xb9f698ad);
    match = re.search(r".+? = (.*)\(?(0x[0-9a-fA-F]{7,8})\)?;", ccode.toString())
    if not match:
        return ""
    cnc_int = int(match.group(2), 16)
    byte_list = []
    byte_list.append(str((cnc_int >> 24) & 0xFF))
    byte_list.append(str((cnc_int >> 16) & 0xFF))
    byte_list.append(str((cnc_int >> 8) & 0xFF))
    byte_list.append(str((cnc_int >> 0) & 0xFF))
    language_id = currentProgram.getLanguageID().toString()
    endian = language_id.split(":")[1]
    # if this instruction uses htonl(), dont reverse bytes
    if match.group(1):
        pass
    elif endian == "LE" or language_id == ARCH_ARM_BE:
        byte_list.reverse()
    cnc = ".".join(byte_list)
    return cnc


def getAttackInitFunc(func_mgr, ifc, monitor, main_func):
    attack_init_func = None
    language_id = currentProgram.getLanguageID().toString()
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        entry_point = func.getEntryPoint()
        refs = getReferencesTo(entry_point)
        # attack_init() only called by main() and Entry Point
        if len(refs) == 0:
            continue
        cand_caller_funcs = []
        for ref in refs:
            cand_caller_func = None
            # in some cases (sh4), getFunctionContaining cannot identify function correctly
            if language_id == ARCH_SH4:
                cand_caller_func = getFunctionBefore(ref.getFromAddress())
            else:
                cand_caller_func = getFunctionContaining(ref.getFromAddress())
            # dont append Entry Point and self function
            if cand_caller_func and cand_caller_func != func:
                cand_caller_funcs.append(cand_caller_func)
        cand_caller_funcs = list(set(cand_caller_funcs))
        # in some cases (mips), ghidra doesnt handle xref correctly
        if language_id not in (ARCH_MIPS_BE, ARCH_MIPS_LE):
            if len(cand_caller_funcs) != 1:
                continue
            if cand_caller_funcs[0] != main_func:
                continue
        ccode = getDecompileCCode(func, ifc, monitor)
        if not ccode:
            continue
        # dont include if/while statements
        match = re.search(r"(if|while) \(.+?\)", ccode.toString())
        if match:
            continue
        # include return 1; statements
        match = re.search(r"return 1;", ccode.toString())
        if not match:
            continue
        lines = ccode.toString().split(";")
        # attack_init() has more than 5 lines
        if len(lines) >= 5:
            attack_init_func = func
            break
    return attack_init_func


def getAttacks(func_mgr, ifc, monitor, attack_init_func):
    attacks = []
    func_names = [func.getName() for func in func_mgr.getFunctions(True)]
    ccode = getDecompileCCode(attack_init_func, ifc, monitor)
    if not ccode:
        return None
    lines = re.split(r"[;{}]", ccode.toString())
    vector = func_name = None
    for line in lines:
        # ; *(undefined *)(ppcVar1 + 1) = 0 ; *(code *)(ppcVar2 + 1) = (code)0x2
        vec_mobj = re.match(r".+? = (\(.+\)|)([0-9a-fA-F|x]+)$", line)
        if vec_mobj:
            vector = int(vec_mobj.group(2), 0)
        # ; *ppcVar1 = attack_udp_generic
        func_mobj = re.match(r".+? = ([0-9a-zA-Z|_]+)$", line)
        if func_mobj:
            tmp_func_name = func_mobj.group(1)
            if tmp_func_name in func_names:
                func_name = tmp_func_name
        # save vector and attack func
        if vector is not None and func_name is not None:
            func = getGlobalFunctions(func_name)[0]
            attack = collections.OrderedDict()
            attack[KEY_VECTOR] = vector
            attack[KEY_NAME] = func.getName()
            attack[KEY_ENTRYPOINT] = func.getEntryPoint().toString()
            attacks.append(attack)
            vector = func_name = None
    if attacks:
        return attacks
    # get vector and attack func from add_attack() (optimization level is not -O3)
    vector = func_name = None
    for line in lines:
        # ; add_attack(0,attack_udp_generic)
        add_mobj = re.match(r"[0-9a-zA-Z|_]+\(([0-9a-fA-F|x]+),([0-9a-zA-Z|_]+)\)$", line)
        if add_mobj:
            vector = int(add_mobj.group(1), 0)
            tmp_func_name = add_mobj.group(2)
            if tmp_func_name in func_names:
                func_name = tmp_func_name
            # save vector and attack func
            if vector is not None and func_name is not None:
                func = getGlobalFunctions(func_name)[0]
                attack = collections.OrderedDict()
                attack[KEY_VECTOR] = vector
                attack[KEY_NAME] = func.getName()
                attack[KEY_ENTRYPOINT] = func.getEntryPoint().toString()
                attacks.append(attack)
                vector = func_name = None
    return attacks


def getUByte(addr):
    return getByte(addr) & 0xFF


def getDecompileCCode(func, ifc, monitor):
    res = ifc.decompileFunction(func, 60, monitor)
    if not res:
        return None
    ccode = res.getCCodeMarkup()
    if not ccode:
        return None
    return ccode


def setFunctionName(func, name):
    if not func:
        return
    original_func_name = func.getName()
    if not original_func_name.startswith("FUN_"):
        return
    func_name = name + "_" + func.getEntryPoint().toString()
    func.setName(func_name, SourceType.USER_DEFINED)
    print("recover: " + original_func_name + " -> " + func_name)
    return


if __name__ == "__main__":
    language_id = currentProgram.getLanguageID().toString()
    if language_id not in LANGS:
        print("error: this script only target for " + str(LANGS))
    listing = currentProgram.getListing()
    func_mgr = currentProgram.getFunctionManager()
    ifc = DecompInterface()
    _ = ifc.setOptions(DecompileOptions())
    _ = ifc.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    defUndefinedFuncs(listing, monitor)
    main_func = main_ccode = None
    resolve_cnc_addr_func = cnc = attack_init_func = attacks = None
    main_func, main_ccode = getMainFunc(func_mgr, ifc, monitor)
    if main_func and main_ccode:
        resolve_cnc_addr_func, cnc = getResolveCncAddrFunc(listing, func_mgr, ifc, monitor, main_func, main_ccode)
        attack_init_func = getAttackInitFunc(func_mgr, ifc, monitor, main_func)
        if attack_init_func:
            attacks = getAttacks(func_mgr, ifc, monitor, attack_init_func)
    # recover function name
    print("")
    print("")
    setFunctionName(main_func, "main")
    setFunctionName(resolve_cnc_addr_func, "resolve_cnc_addr")
    setFunctionName(attack_init_func, "attack_init")
    for attack in attacks:
        attack_func = getFunctionAt(toAddr(attack[KEY_ENTRYPOINT]))
        setFunctionName(attack_func, "attack_vector" + str(attack[KEY_VECTOR]))
    print("done")
    print("")
    print("")
