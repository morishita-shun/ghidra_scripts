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
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor


KEY_NAME = "name"
KEY_VECTOR = "vector"
KEY_ENTRYPOINT = "entrypoint"

MNE_CALL = "CALL"
MNE_CALLIND = "CALLIND"
MNE_INT_XOR = "INT_XOR"

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


def getScannerKey(func_mgr, ifc, monitor):
    add_auth_entry_func = deobf_func = scanner_key = None
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        ccode = getDecompileCCode(func, ifc, monitor)
        if not ccode:
            continue
        roop_strs = re.findall(r"do \{.+?\} while", ccode.toString())
        if len(roop_strs) == 0:
            # sparc uses while(true) statement
            roop_strs = re.findall(r"while\( true \) \{.+?\}", ccode.toString())
        # add_auth_entry_func has two while statements
        if len(roop_strs) == 2:
            keys = []
            for roop_str in roop_strs:
                # ; *(byte *)(iVar4 + (int)pvVar3) = *(byte *)(iVar4 + (int)pvVar3) ^ 0xb4;
                match = re.search(r".+? = .+? \^ ([0-9a-fA-F|x]+);", roop_str)
                if not match:
                    continue
                key = int(match.group(1), 0)
                # check 1 byte key
                if 0 <= key <= 255:
                    keys.append(key)
            if len(keys) == 2:
                if None not in keys and keys[0] == keys[1]:
                    add_auth_entry_func = func
                    scanner_key = keys[0]
                    break
        else:
            # maybe this is deobf_func (this malware is not using optimization level -O3)
            # ; while ((int)lVar2 < *param_2) {
            roop_strs = re.findall(r"while \(.+? \< .+?\) \{.+?\}", ccode.toString())
            if len(roop_strs) == 0:
                # get for statement
                # ; for (iVar1 = 0; iVar1 < *param_2; iVar1 = iVar1 + 1) {
                roop_strs = re.findall(r"for \(.+?; .+?; .+?\) \{.+?\}", ccode.toString())
            if len(roop_strs) != 1:
                continue
            # handle more than one xor statement
            # ; *(byte *)(lVar3 + lVar2) = *(byte *)(lVar3 + lVar2) ^ 3;
            xor_strs = re.findall(r".+? = .+? \^ [0-9a-fA-F|x]+;", roop_strs[0])
            if len(xor_strs) == 0:
                continue
            for xor_str in xor_strs:
                match = re.search(r".+? = .+? \^ ([0-9a-fA-F|x]+);", xor_str)
                if not match:
                    continue
                key = int(match.group(1), 0)
                # check 1 byte key
                if 0 <= key <= 255:
                    if not scanner_key:
                        scanner_key = key
                    else:
                        scanner_key ^= key
            if scanner_key:
                deobf_func = func
                add_auth_entry_func = getModeCallerFunc(deobf_func)
    return add_auth_entry_func, scanner_key


def getModeCallerFunc(callee_func):
    caller_func = None
    language_id = currentProgram.getLanguageID().toString()
    entry_point = callee_func.getEntryPoint()
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
    # use mode function for caller_func
    if len(cand_caller_funcs) >= 1:
        caller_func = collections.Counter(cand_caller_funcs).most_common(1)[0][0]
    return caller_func


def getTableKey(listing, func_mgr):
    table_lock_val_funcs = []
    table_key = table_original_key_str = table_base_addr = None
    language_id = currentProgram.getLanguageID().toString()
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        instruct_mnemonics_list = []
        first_varnodes_list = []
        second_varnodes_list = []
        instructs = list(listing.getInstructions(func.getBody(), True))
        for instruct in instructs:
            pcode = instruct.getPcode()
            for entry in pcode:
                if entry.getMnemonic() != MNE_INT_XOR:
                    continue
                # ; (unique, 0x7800, 1) INT_XOR (unique, 0x7800, 1) , (register, 0xc, 1)
                # m68k ; (unique, 0x5800, 1) INT_XOR (register, 0x17, 1) , (unique, 0x5800, 1)
                varnodes = entry.getInputs()
                first_varnode = varnodes[0]
                second_varnode = varnodes[1]
                if first_varnode.toString() == second_varnode.toString():
                    continue
                first_type = parseVarnode(first_varnode)[0]
                second_type = parseVarnode(second_varnode)[0]
                if language_id == ARCH_M68K:
                    if first_type != "register" and second_type == "register":
                        continue
                else:
                    if first_type == "register" and second_type != "register":
                        continue
                instruct_mnemonics_list.append(instruct.getMnemonicString())
                first_varnodes_list.append(first_varnode)
                second_varnodes_list.append(second_varnode)
                break
        instruct_mnemonics_set = set(instruct_mnemonics_list)
        first_varnodes_set = set(first_varnodes_list)
        second_varnodes_set = set(second_varnodes_list)
        if (len(instruct_mnemonics_set) == 1
                and len(second_varnodes_list) == 4
                and len(second_varnodes_set) == 1):
            # in most cases, second_varnode is same
            pass
        elif (len(instruct_mnemonics_set) == 1
                and len(second_varnodes_list) == 4
                and len(first_varnodes_set) == 1):
            # x86_64 uses same first_varnode
            pass
        elif (len(instruct_mnemonics_set) == 1
                and len(second_varnodes_list) == 4
                and len(second_varnodes_set) == 2):
            # sometimes mips uses two different registers
            pass
        else:
            continue
        # check table_key
        target_func_flag = False
        data_addrs = []
        for instruct in instructs:
            try:
                refs = getReferencesFrom(instruct.getAddress())
                if len(refs) == 0:
                    continue
                for ref in refs:
                    data_addr = ref.getToAddress()
                    if not data_addr.isMemoryAddress():
                        continue
                    data_addrs.append(data_addr)
                    bytes = getDataAt(data_addr).getValue()
                    if not isinstance(bytes, Scalar):
                        continue
                    if bytes.bitLength() != 32:
                        continue
                    # original table_key is 4 bytes (32 bits)
                    target_func_flag = True
                    table_original_key_str = format(bytes.getUnsignedValue(), "#010x")
                    table_key = int(table_original_key_str[2:4], 16) ^ \
                            int(table_original_key_str[4:6], 16) ^ \
                            int(table_original_key_str[6:8], 16) ^ \
                            int(table_original_key_str[8:10], 16)
                    table_lock_val_funcs.append(func)
            except:
                continue
        if target_func_flag:
            # mode data_addrs is table_base_addr
            table_base_addr = collections.Counter(data_addrs).most_common(1)[0][0]
    return table_lock_val_funcs, table_key, table_original_key_str, table_base_addr


def getTableInitFunc(listing, ifc, monitor, func_mgr, table_key, xor_string_count_threshold=3):
    def _getCandUtilMemcpyFuncs(cand_caller_func):
        res = ifc.decompileFunction(cand_caller_func, 60, monitor)
        if not res:
            return None
        high_func = res.getHighFunction()
        pcodes = high_func.getPcodeOps()
        # get target_funcs: malloc() or util_memcpy()
        cand_util_memcpy_funcs = []
        for pcode in pcodes:
            if pcode.getMnemonic() not in (MNE_CALL, MNE_CALLIND):
                continue
            instruct_addr = pcode.getSeqnum().getTarget()
            ref = getReferencesFrom(instruct_addr)
            if len(ref) == 0:
                continue
            ref_func = getFunctionAt(ref[0].getToAddress())
            if ref_func:
                cand_util_memcpy_funcs.append(ref_func)
        return cand_util_memcpy_funcs
    table_init_func = util_memcpy_func = add_entry_func = None
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        cand_table_init_func = cand_add_entry_func = None
        # check func has xor strings (default threshold is 3)
        xor_string_count = 0
        for instruct in listing.getInstructions(func.getBody(), True):
            refs = getReferencesFrom(instruct.getAddress())
            if len(refs) == 0:
                continue
            for ref in refs:
                data_addr = ref.getToAddress()
                data_symbol = getSymbolAt(data_addr)
                try:
                    # check DAT_*/s_* address
                    if not data_symbol.toString().startswith(("DAT_", "s_")):
                        continue
                    bytes = []
                    # max size (1024) of bytes
                    for count in range(1024):
                        byte = getUByte(data_addr.add(count))
                        # null
                        if byte == 0:
                            break
                        else:
                            bytes.append(byte)
                    # last byte of xor string is table_key
                    if len(bytes) >= 2 and bytes[-1] == table_key:
                        xor_string_count += 1
                except:
                    continue
            if xor_string_count >= xor_string_count_threshold:
                cand_table_init_func = func
                break
        if cand_table_init_func:
            cand_util_memcpy_funcs = _getCandUtilMemcpyFuncs(cand_table_init_func)
            if len(set(cand_util_memcpy_funcs)) == 2:
                pass
            elif len(set(cand_util_memcpy_funcs)) == 1:
                # maybe this is add_entry_func (this malware is not using optimization level -O3)
                cand_add_entry_func = cand_util_memcpy_funcs[0]
                cand_util_memcpy_funcs = _getCandUtilMemcpyFuncs(cand_add_entry_func)
                if len(set(cand_util_memcpy_funcs)) == 2:
                    pass
                else:
                    continue
            else:
                continue
            # get mode function
            cand_util_memcpy_func1 = collections.Counter(cand_util_memcpy_funcs).most_common(2)[0][0]
            cand_func1_instructs = list(listing.getInstructions(cand_util_memcpy_func1.getBody(), True))
            # get second mode function
            cand_util_memcpy_func2 = collections.Counter(cand_util_memcpy_funcs).most_common(2)[1][0]
            cand_func2_instructs = list(listing.getInstructions(cand_util_memcpy_func2.getBody(), True))
            # minimum function is util_memcpy()
            if len(cand_func1_instructs) > len(cand_func2_instructs):
                util_memcpy_func = cand_util_memcpy_func2
            else:
                util_memcpy_func = cand_util_memcpy_func1
            table_init_func = cand_table_init_func
            add_entry_func = cand_add_entry_func
            break
    return table_init_func, util_memcpy_func, add_entry_func


def getTableRetrieveValFunc(table_lock_val_funcs, table_base_addr):
    table_retrieve_val_func = None
    refs = getReferencesTo(table_base_addr)
    for ref in refs:
        cand_table_retrieve_val_func = getFunctionContaining(ref.getFromAddress())
        # exclude None from cand_table_retrieve_val_func
        if cand_table_retrieve_val_func and cand_table_retrieve_val_func not in table_lock_val_funcs:
            table_retrieve_val_func = cand_table_retrieve_val_func
            break
    return table_retrieve_val_func


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
    attack_init_func = attack_init_ccode = None
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
            attack_init_ccode = ccode
            break
    return attack_init_func, attack_init_ccode


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


def getCallocFunc(attack_init_ccode):
    calloc_func = None
    # ; calloc(1, sizeof (struct attack_method));
    # ; FUN_08054a2c(1,8);
    match = re.search(r"(FUN_.+?)\(1,8\);", attack_init_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(1,8\)", match.group(0).split(";")[-2])
    if not match:
        return None
    calloc_func = getFunctionFromName(match.group(1))
    return calloc_func


def getReallocFunc(attack_init_ccode):
    realloc_func = None
    # ; realloc(methods, (methods_len + 1) * sizeof (struct attack_method *));
    # ; FUN_000149a0(uVar1,(uVar5 + 1) * 4);
    # ; FUN_08054b24(DAT_08059700,(uint)DAT_080596fc * 4 + 4);
    match = re.search(r"(FUN_.+?)\(.+?,.+? \* 4.*?\);", attack_init_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(.+?,.+? \* 4.*?\)", match.group(0).split(";")[-2])
    if not match:
        return None
    realloc_func = getFunctionFromName(match.group(1))
    return realloc_func


def getCloseFunc(main_ccode):
    close_func = None
    # ; FUN_000134e0(0);FUN_000134e0(1);FUN_000134e0(2);
    match = re.search(r";(FUN_.+?)\(0\);(FUN_.+?)\(1\);(FUN_.+?)\(2\);", main_ccode.toString())
    if not match:
        return None
    close_func = getFunctionFromName(match.group(2))
    return close_func


def getWriteFunc(main_ccode):
    write_func = None
    # ; write(STDOUT, "\n", 1);
    # ; FUN_00013768(1,uVar12,local_2c);FUN_00013768(1,&DAT_000189b0,1);
    match = re.search(r";(FUN_.+?)\(1,.+?,.+?\);(FUN_.+?)\(1,.+?,1\);", main_ccode.toString())
    if not match:
        return None
    write_func = getFunctionFromName(match.group(2))
    return write_func


def getIoctlFunc(main_ccode):
    ioctl_func = None
    # ; FUN_00013548(iVar10,0x80045704,&local_30);
    match = re.search(r";(FUN_.+?)\(.+?,0x80045704,.+?\);", main_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(.+?,0x80045704,.+?\)", match.group(0).split(";")[-2])
    if not match:
        return None
    ioctl_func = getFunctionFromName(match.group(1))
    return ioctl_func


def getFcntlFunc(main_ccode):
    fcntl_func = None
    # ; fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));
    # ; FUN_000133ec(piVar15,4,uVar11 | 0x800);
    match = re.search(r";(FUN_.+?)\(.+?,4,.+?0x800\);", main_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(.+?,4,.+?0x800\)", match.group(0).split(";")[-2])
    if not match:
        return None
    fcntl_func = getFunctionFromName(match.group(1))
    return fcntl_func


def getOpenFunc(main_ccode):
    open_func = None
    # ; iVar10 = FUN_000135c4("/dev/watchdog",2);
    match = re.search(r";.+? = (FUN_.+?)\(\"/dev/watchdog\",2\);", main_ccode.toString())
    if not match:
        return None
    open_func = getFunctionFromName(match.group(1))
    return open_func


def getSocketFunc(main_ccode):
    socket_func = None
    # ; socket(AF_INET, SOCK_STREAM, 0)
    # ; FUN_00013e40(2,1,0)
    match = re.search(r"(FUN_.+?)\(2,1,0\)", main_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(2,1,0\)", match.group(0).split(" ")[-1])
    if not match:
        return None
    socket_func = getFunctionFromName(match.group(1))
    return socket_func


def getRecvFunc(main_ccode):
    recv_func = None
    # ; recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
    # ; FUN_00013d50(DAT_000214f8,&local_26,2,0x4002);
    match = re.search(r"(FUN_.+?)\(.+?,.+?,.+?,0x4002\);", main_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(.+?,.+?,.+?,0x4002\)", match.group(0).split(";")[-2])
    if not match:
        return None
    recv_func = getFunctionFromName(match.group(1))
    return recv_func


def getSendFunc(main_ccode):
    send_func = None
    # ; send(fd_serv, id_buf, id_len, MSG_NOSIGNAL);
    # ; FUN_00013db0(*puVar14,&local_26,1,0x4000);
    match = re.search(r"(FUN_.+?)\(.+?,.+?,1,0x4000\);", main_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(.+?,.+?,1,0x4000\)", match.group(0).split(";")[-2])
    if not match:
        return None
    send_func = getFunctionFromName(match.group(1))
    return send_func


def getKillExitFunc(main_ccode):
    kill_func = exit_func = None
    # ; kill(pgid * -1, 9); exit(0);
    # ; FUN_00013598(-iVar10,9);FUN_00015430(0);
    match = re.search(r";(FUN_.+?)\(.+?,9\);(FUN_.+?)\(0\);", main_ccode.toString())
    if not match:
        return None, None
    lines = match.group(0).split(";")
    match = re.search(r"(FUN_.+?)\(.+?,9\)", lines[-3])
    if not match:
        kill_func = None
    else:
        kill_func = getFunctionFromName(match.group(1))
    match = re.search(r"(FUN_.+?)\(0\)", lines[-2])
    if not match:
        exit_func = None
    else:
        exit_func = getFunctionFromName(match.group(1))
    return kill_func, exit_func


def getConnectFunc(main_ccode):
    connect_func = None
    # ; connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof (struct sockaddr_in));
    # ; FUN_00013c9c(DAT_000214f8,&DAT_00023770,0x10);
    match = re.search(r";(FUN_.+?)\(.+?,.+?,0x10\);", main_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(.+?,.+?,0x10\)", match.group(0).split(";")[-2])
    if not match:
        return None
    connect_func = getFunctionFromName(match.group(1))
    return connect_func


def getPrctlFunc(main_ccode):
    prctl_func = None
    # ; prctl(PR_SET_NAME, name_buf);
    # ; FUN_00013620(0xf,piVar15);
    match = re.search(r";(FUN_.+?)\(0xf,.+?\);", main_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(0xf,.+?\)", match.group(0).split(";")[-2])
    if not match:
        return None
    prctl_func = getFunctionFromName(match.group(1))
    return prctl_func


def getSignalFunc(main_ccode):
    signal_func = None
    # ; signal(SIGCHLD, SIG_IGN);
    # ; FUN_00013ec8(0x11,1);
    match = re.search(r";(FUN_.+?)\(0x11,1\);", main_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(0x11,1\)", match.group(0).split(";")[-2])
    if not match:
        return None
    signal_func = getFunctionFromName(match.group(1))
    return signal_func


def getUtilZeroFunc(main_ccode):
    util_zero_func = None
    # ; util_zero(id_buf, 32);
    # ; FUN_00012be8(auStack_b2,0x20);
    match = re.search(r";(FUN_.+?)\(.+?,0x20\);", main_ccode.toString())
    if not match:
        return None
    match = re.search(r"(FUN_.+?)\(.+?,0x20\)", match.group(0).split(";")[-2])
    if not match:
        return None
    util_zero_func = getFunctionFromName(match.group(1))
    return util_zero_func


def getUtilStrcpyFunc(main_ccode):
    util_strcpy_func = None
    # ; util_strcpy(id_buf, args[1]);
    # ; FUN_00012b7c(auStack_b2,param_2[1]);
    match = re.search(r";(FUN_.+?)\(.+?,param_2\[1\]\);", main_ccode.toString())
    if not match:
        return None
    match = re.search(r"\{(FUN_.+?)\(.+?,param_2\[1\]\)", match.group(0).split(";")[-2])
    if not match:
        return None
    util_strcpy_func = getFunctionFromName(match.group(1))
    return util_strcpy_func


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


def parseVarnode(varnode):
    return varnode.toString().strip("()").split(", ")


def getFunctionFromName(name):
    func = None
    funcs = getGlobalFunctions(name)
    if len(funcs) != 0:
        func = funcs[0]
    return func


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
    ifc = DecompInterface()
    _ = ifc.setOptions(DecompileOptions())
    _ = ifc.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    defUndefinedFuncs(listing, monitor)
    add_auth_entry_func = scanner_init_func = scanner_key = auth_tables = None
    table_lock_val_funcs = table_init_func = util_memcpy_func = None
    add_entry_func = table_retrieve_val_func = table_key = None
    table_original_key_str = table_base_addr = tables = None
    main_func = main_ccode = None
    close_func = write_func = ioctl_func = fcntl_func = open_func = socket_func = None
    recv_func = send_func = kill_func = exit_func = connect_func = prctl_func = None
    singal_func = util_zero_func = util_strcpy_func = None
    resolve_cnc_addr_func = cnc = None
    attack_init_func = attack_init_ccode = attacks = None
    calloc_func = realloc_func = None
    add_auth_entry_func, scanner_key = getScannerKey(func_mgr, ifc, monitor)
    if add_auth_entry_func and scanner_key:
        scanner_init_func = getModeCallerFunc(add_auth_entry_func)
    table_lock_val_funcs, table_key, table_original_key_str, table_base_addr = getTableKey(
            listing, func_mgr
            )
    if table_lock_val_funcs and table_key and table_original_key_str and table_base_addr:
        table_init_func, util_memcpy_func, add_entry_func = getTableInitFunc(
                listing, ifc, monitor, func_mgr, table_key
                )
        table_retrieve_val_func = getTableRetrieveValFunc(
                table_lock_val_funcs, table_base_addr
                )
    main_func, main_ccode = getMainFunc(func_mgr, ifc, monitor)
    if main_func and main_ccode:
        close_func = getCloseFunc(main_ccode)
        write_func = getWriteFunc(main_ccode)
        ioctl_func = getIoctlFunc(main_ccode)
        fcntl_func = getFcntlFunc(main_ccode)
        open_func = getOpenFunc(main_ccode)
        socket_func = getSocketFunc(main_ccode)
        recv_func = getRecvFunc(main_ccode)
        send_func = getSendFunc(main_ccode)
        kill_func, exit_func = getKillExitFunc(main_ccode)
        connect_func = getConnectFunc(main_ccode)
        prctl_func = getPrctlFunc(main_ccode)
        signal_func = getSignalFunc(main_ccode)
        util_zero_func = getUtilZeroFunc(main_ccode)
        util_strcpy_func = getUtilStrcpyFunc(main_ccode)
        resolve_cnc_addr_func, cnc = getResolveCncAddrFunc(listing, func_mgr, ifc, monitor, main_func, main_ccode)
        attack_init_func, attack_init_ccode = getAttackInitFunc(func_mgr, ifc, monitor, main_func)
        if attack_init_func and attack_init_ccode:
            attacks = getAttacks(func_mgr, ifc, monitor, attack_init_func)
            calloc_func = getCallocFunc(attack_init_ccode)
            realloc_func = getReallocFunc(attack_init_ccode)
    # recover function name
    print("")
    print("")
    setFunctionName(add_auth_entry_func, "add_auth_entry")
    setFunctionName(scanner_init_func, "scanner_init")
    for index, table_lock_val_func in enumerate(table_lock_val_funcs):
        setFunctionName(table_lock_val_func, "table_lock_val" + str(index+1))
    setFunctionName(table_init_func, "table_init")
    setFunctionName(util_memcpy_func, "util_memcpy")
    setFunctionName(add_entry_func, "add_entry")
    setFunctionName(table_retrieve_val_func, "table_retrieve_val")
    setFunctionName(main_func, "main")
    setFunctionName(resolve_cnc_addr_func, "resolve_cnc_addr")
    setFunctionName(attack_init_func, "attack_init")
    if attacks:
        for attack in attacks:
            attack_func = getFunctionAt(toAddr(attack[KEY_ENTRYPOINT]))
            setFunctionName(attack_func, "attack_vector" + str(attack[KEY_VECTOR]))
    setFunctionName(calloc_func, "calloc")
    setFunctionName(realloc_func, "realloc")
    setFunctionName(close_func, "close")
    setFunctionName(write_func, "write")
    setFunctionName(ioctl_func, "ioctl")
    setFunctionName(fcntl_func, "fcntl")
    setFunctionName(open_func, "open")
    setFunctionName(socket_func, "socket")
    setFunctionName(recv_func, "recv")
    setFunctionName(send_func, "send")
    setFunctionName(kill_func, "kill")
    setFunctionName(exit_func, "exit")
    setFunctionName(connect_func, "connect")
    setFunctionName(prctl_func, "prctl")
    setFunctionName(signal_func, "signal")
    setFunctionName(util_zero_func, "util_zero")
    setFunctionName(util_strcpy_func, "util_strcpy")
    print("done")
    print("")
    print("")
