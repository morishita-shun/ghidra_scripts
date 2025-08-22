# Decode IP address from bytes and add EOL comment. 
# @author Shun Morishita
# @category Binary
# @menupath Tools.Decode IP from bytes
# @toolbar

import socket

current_addr = currentAddress
listing = currentProgram.getListing()
instr = listing.getInstructionAt(current_addr)

if instr is None:
    print("No instruction at the current address")
else:
    # second operand (0-based)
    op_index = 1
    if instr.getNumOperands() <= op_index:
        print("Second operand does not exist")
    else:
        op_objects = instr.getOpObjects(op_index)
        if len(op_objects) != 1:
            print("Second operand is not a single value")
        else:
            op = op_objects[0]
            val = None
            try:
                # Extract integer value
                val = op.getValue()
            except:
                pass
            if val is not None and 0 <= val <= 0xFFFFFFFF:
                # Convert to 4 bytes (little-endian)
                ip_bytes = "".join([chr((val >> shift) & 0xFF) for shift in (0, 8, 16, 24)])
                ip_str = socket.inet_ntoa(ip_bytes)
                # Add EOL comment
                if getEOLComment(instr.getAddress()):
                    print(str(current_addr) + " - EOL comment already exists")
                else:
                    setEOLComment(instr.getAddress(), "IP: " + ip_str)
                    print(str(current_addr) + " - IP comment added: " + ip_str)
            else:
                print("Second operand is not a 4-byte integer")