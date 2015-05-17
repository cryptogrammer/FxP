##
##bitarray library is to convert to and from bitarrays and strings
##
##
##
##
import bitarray
import math

test_message = "Hello World"

## convert to bitstring
ba = bitarray.bitarray()
ba.fromstring(test_message)
bitRepresentation = ba
print(bitRepresentation)

## converting back to string
x = (ba.tostring()).encode('ascii','ignore')

## F.E.C

## Parity matrix

def buildParity(bitRepresentation):
	parityArray = []
	bitString = bitRepresentation.to01()
	arrayDimension = int(math.ceil(math.sqrt(len(bitstring)))) + 1
	parityArray = [[0 for x in range(arrayDimension)] for x in range(arrayDimension)]
	
	## populate the parity array
	rowCount = 0
	colCount = 0
	for x in range(arrayDimension-1):
		for y in range(arrayDimension-1):
			parityArray[x][y] = bitString[x+y]
			if(parityArray[x][y] == 1):
				rowCount = rowCount + 1
		if(rowCount % 2 != 0):
			parityArray[x][y+1] = 1
		rowCount = 0
	
	for j in range(arrayDimension-1):
		for i in range(arrayDimension-1):
			if(parityArray[i][j] == 1):
				colCount = colCount + 1
		if(colCount % 2 != 0):
			parityArray[arrayDimension-1][j] = 1
	return parityArray

def convertToParityString(parityArray):
	returnString = ""
	for k in range(len(parityArray)):
		for m in range(len(parityArray)):
			returnString = returnString + parityArray[k][m]
	return returnString

def checkAndFixErrors(parityBitString):
	arrayDimension = int(math.sqrt(len(parityBitString)))
	rowSums = []
	rowSum = 0
	colSums = [0 for x in range(arrayDimension)]
	for k in range(len(parityBitString)):
		if(k != 0 and k % (arrayDimension-1) == 0):
			rowSums.append(rowSum)
			rowSum = 0
		rowSum = rowSum + int(parityBitString[k])
		colSums[k % (arrayDimension - 1)]  = colSums[k % (arrayDimension - 1)] + int(parityBitString[k])
	
	## implement ot check error and fix it.
