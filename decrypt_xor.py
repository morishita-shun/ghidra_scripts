# Use 1-byte key to XOR bytes in selection.
# @author Shun Morishita
# @category Selection

xor_key = askInt("1-byte XOR key", "0x00-0xFF")
addrs = currentSelection.getAddresses(True)

dec_string = ""
for addr in addrs:
    byte = getByte(addr)
    if not byte:
        continue
    dec_string += chr(byte ^ xor_key)

dec_string
