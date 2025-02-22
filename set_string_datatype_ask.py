# Set datatype to String from dialog.
# @author Shun Morishita
# @category Data Types

from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import DefaultDataType, StringDataType

listing = currentProgram.getListing()
start_addr = toAddr(askString("Start Address", "start_addr"))
end_addr = toAddr(askString("End Address", "end_addr"))
addrs = AddressSet(start_addr, end_addr).getAddresses(True)

print("start_addr: " + str(start_addr))
print("end_addr: " + str(end_addr))
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
