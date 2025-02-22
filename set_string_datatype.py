# Set datatype to String in selection.
# @author Shun Morishita
# @category Selection

from ghidra.program.model.data import DefaultDataType, StringDataType

listing = currentProgram.getListing()
addrs = currentSelection.getAddresses(True)

for addr in addrs:
    symbol = getSymbolAt(addr)
    if not symbol:
        continue
    data = listing.getDataAt(addr)
    if not data:
        continue
    data_type = data.getDataType()
    if isinstance(data_type, DefaultDataType):
        data = listing.createData(addr, StringDataType())
