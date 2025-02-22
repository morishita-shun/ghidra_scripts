# Print each symbol's hex string in selection.
# @author Shun Morishita
# @category Selection

addrs = currentSelection.getAddresses(True)

while addrs.hasNext():
    addr = addrs.next()
    symbol = getSymbolAt(addr)
    if not symbol:
        continue
    # print bytes until next symbol/end
    byte_array = bytearray()
    while True:
        byte = getByte(addr)
        if not byte:
            break
        if byte == 0:
            break
        byte_array.append(byte)
        if addrs.hasNext():
            addr = addrs.next()
        else:
            break
    if len(byte_array) > 0:
        print("".join(["\\x{:02x}".format(byte) for byte in byte_array]))
