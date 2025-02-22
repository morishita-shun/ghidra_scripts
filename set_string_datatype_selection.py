# Set datatype to String in selection.
# @author Shun Morishita
# @category Data Types

from ghidra.program.model.data import DefaultDataType, StringDataType

listing = currentProgram.getListing()
addrs = currentSelection.getAddresses(True)

print("start_addr: " + str(currentSelection.getMinAddress()))
print("end_addr: " + str(currentSelection.getMaxAddress()))
print("")

for addr in addrs:
    symbol = getSymbolAt(addr)
    if not symbol:
        continue
    data = listing.getDataAt(addr)
    if not data:
        continue
    data_type = data.getDataType()
    #if isinstance(data_type, DefaultDataType):
    if isinstance(data_type, StringDataType):
        print("Pass: " + str(symbol))
    else:
        data = listing.createData(addr, StringDataType())
        print("Set: " + str(symbol))
