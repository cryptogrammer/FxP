def checksum(message):
	retVal = 0
	for ch in message:
		retVal = (retVal>>1) + ((retVal & 1) << 31)
		retVal += ch
		retVal &= 0xffffffff
	return retVal
