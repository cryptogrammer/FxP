import sys
from socket import *
import random
import struct
import rsa
import time
import os
ECHO_PORT = 50000 + 7
BUFSIZE = 1500
serverInitialSeq = int(random.random()*10000)
serverInitialSeqCopy = serverInitialSeq + 2
DEFAULT_SENDER_WINDOW_SIZE = 5
serverRecieveBuffer = {}
clientSendBuffer = []
count = 0
clientRecieveBuffer = {}
DEFAULT_TIMEOUT_VALUE = 2
functionFlag = False
finalConn = False
bindport = 0

def main():
	global functionFlag
	if len(sys.argv) < 3:
		usage()
	if sys.argv[1] == '-s':
		server()

def usage():
	sys.stdout = sys.stderr
	print 'Usage: udpecho -s [port] (server)'
	print 'or:    udpecho -c bindport desthost [destport] <file (client)'
	sys.exit(2)

def createServerFile(buffer):
	fileString = ""
	for k in sorted(serverRecieveBuffer.keys()):
		fileString = fileString + serverRecieveBuffer[k]
	f = open("serverReceivedFile.txt",'w')
	f.write(fileString)
	f.close()

def checksumFunction(message):
	retVal = 0
	message = str(message)
	for ch in message:
		retVal = (retVal>>1) + ((retVal & 1) << 31)
		retVal += ord(ch)
		retVal &= 0xffffffff
	return retVal

def server():
	global finalConn
	global serverRecieveBuffer
	global DEFAULT_TIMEOUT_VALUE
	global clientSendBuffer
	global count
	global bindport
	global serverInitialSeq
	global serverInitialSeqCopy
	serverInitialSeqCopy = serverInitialSeqCopy + 1
	## dictionary of sequence numbers mapped to message+
	packetWindow = {}
	(spub_key, spriv_key) = rsa.newkeys(512)
	flag = True
	if len(sys.argv) > 2:
		port = eval(sys.argv[2])
		bindport = port
	else:
		port = ECHO_PORT
	s = socket(AF_INET, SOCK_DGRAM)
	s.bind(('', port))
	print 'UDP server ready'
	while 1:
		data, addr = s.recvfrom(BUFSIZE)
		header = data[:27]
		header = struct.unpack("!HHLLBHLLL", header)
		headerFlags = header[4]
		headerFlags = bin(headerFlags)[2:].zfill(4)
		nextACKNumberserver = header[2] + 1 ##SYN number + 1
		chksum = header[6]
		if(str(checksumFunction(data[27:])) == str(chksum)):
			if(headerFlags[1] == '1' and headerFlags[0] == '0' and headerFlags[2] == '0' and headerFlags[3] == '0'):
				if(data[27:30] == 'get'):
					print "Server received GET request..."
					## read in file
					f = open(data[30:], 'r')
					
					## convert file to string
					fileString = ""
					lines = f.readlines()
					for line in lines:
						fileString = fileString + line

					## store in packet ready sizes of maximum 1473 bytes
					i = 0
					while(i < len(fileString)-1436):
						clientSendBuffer.append(fileString[i:i+1436])
						i = i + 1436
					clientSendBuffer.append(fileString[i:])
					# print clientSendBuffer
					## initializing client window with default window size
					initialPacketWindowIndex = 0
					while(initialPacketWindowIndex < DEFAULT_SENDER_WINDOW_SIZE and initialPacketWindowIndex < len(clientSendBuffer)):
						packetWindow[serverInitialSeqCopy+initialPacketWindowIndex] = (clientSendBuffer[initialPacketWindowIndex],0)
						initialPacketWindowIndex = initialPacketWindowIndex + 1
					print "Receive request confirmation sent with sequence #"+ (str(serverInitialSeq))
					serverSend(s,port, str(len(clientSendBuffer)), addr,10, nextACKNumberserver)
					while(1):
						if(len(packetWindow)==0):
							break
						serverInitialSeq = serverInitialSeqCopy
						current = serverInitialSeq
						firstUnackedPacket = serverInitialSeq
						while(current < serverInitialSeqCopy+len(clientSendBuffer) and not finalConn):
							s.setblocking(0)
							clientSend(s,bindport, packetWindow[current][0], addr, 3, 0)
							count = count + 1
							try:
								serverACK, addr = s.recvfrom(1500)
								if(serverACK != None):
									header, headerFlags, nextACKNumberclient, ACKedPacketSequenceNumber = extractHeader(serverACK)
									if(ACKedPacketSequenceNumber < clientInitialSeqCopy+len(clientSendBuffer)):
										packetWindow[ACKedPacketSequenceNumber] = (packetWindow[ACKedPacketSequenceNumber][0],1)
									print "ACK found for sequence #" + str(ACKedPacketSequenceNumber)
									update = updateFUP(firstUnackedPacket, ACKedPacketSequenceNumber, packetWindow)
									if(update != None):
										firstUnackedPacket = update
										clientInitialSeq = firstUnackedPacket
										current = firstUnackedPacket
							except:
								print "No ACK found, transmitting other packets now..."
							current = current + 1
							serverInitialSeq = current
							if(count >= DEFAULT_SENDER_WINDOW_SIZE or len(packetWindow) < DEFAULT_SENDER_WINDOW_SIZE):
								s.setblocking(1)
								s.settimeout(DEFAULT_TIMEOUT_VALUE)
								retransmitBool = True
								while(retransmitBool):
									try:
										serverACK, addr = s.recvfrom(1500)
										header, headerFlags, nextACKNumberclient, ACKedPacketSequenceNumber = extractHeader(serverACK)
										if(ACKedPacketSequenceNumber < serverInitialSeqCopy+len(clientSendBuffer)):				
											packetWindow[ACKedPacketSequenceNumber] = (packetWindow[ACKedPacketSequenceNumber][0],1)
										update = updateFUP(firstUnackedPacket, ACKedPacketSequenceNumber, packetWindow)
										print "ACK RECEIVED for seq #" + str(ACKedPacketSequenceNumber)
										if(update != None):
											current = update
											firstUnackedPacket = update
											retransmitBool = False
											serverInitialSeq = firstUnackedPacket
										if(len(packetWindow)==0):
											finalConn=True
											break
									except:
										print "ACK not received..retransmitting packet with sequence #" + str(firstUnackedPacket)
										retransmit(s,bindport,packetWindow, firstUnackedPacket, addr, 0)
					s.settimeout(None)
				elif(data[27:] == 'post'):
					print "Server received POST request"
					serverSend(s,port, str(len(clientSendBuffer)), addr,10, nextACKNumberserver)
					MESSAGE = "Ack"
					serverSend(s,port,MESSAGE,addr,2, nextACKNumberserver)

			elif (headerFlags[2] == '1' and headerFlags[0] == '0'): #SYN 1 ACK 0
				MESSAGE =  spub_key
				if(flag):
					print "SYN recieved from client at "+ str(addr) + "\n"
				serverSend(s,port, MESSAGE, addr,1, nextACKNumberserver)

			elif(headerFlags[2] == '1' and headerFlags[0] == '1'): #SYN 1 ACK 1 
				MESSAGE = "Ack"
				if(flag):
					print "SYN ACK recieved from client at "+ str(addr) + "\n"
				serverSend(s,port,MESSAGE,addr,2, nextACKNumberserver)
				print "Server SENT LAST ACK FOR HANDSHAKE"

			elif((headerFlags[0] == '0' and headerFlags[3] == '1')):
				MESSAGE = "closing Ack.."
				createServerFile(serverRecieveBuffer)
				if(flag):
					print "FIN: I recieved from client at "+ str(addr) + "\n"
				serverSend(s,port,MESSAGE,addr,3, nextACKNumberserver)
				MESSAGE = "Server Fin"
				serverSend(s,port,MESSAGE,addr,4, nextACKNumberserver)
			elif(headerFlags[0] == '1' and headerFlags[3] == '1'):
				print("Fin J's ACK Received. Server closing.")
				break
			else:
				MESSAGE = "ACK"
				if(not header[2] in serverRecieveBuffer):
					serverRecieveBuffer[header[2]] = data[27:]
				serverSend(s,port,MESSAGE,addr,2, nextACKNumberserver)
		else:
			print "DID NOT MATCH CHECKSUM, Dropping packet"
	createServerFile(serverRecieveBuffer)

def serverSend(s,src_port, message, addr, state, nextACKNumber = 0):
	global serverInitialSeq
	if(state == 1):
		header = generateHeader(src_port, addr[1], serverInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 1, 0, 1, 0, message)
		s.sendto(header+str(message), addr)
		print "Server sending SYN ACK + public key with sequence  #"+ str(serverInitialSeq) + " Next sequence expected: " + str(nextACKNumber)
		serverInitialSeq = serverInitialSeq + 1
	if(state == 2):
		header = generateHeader(src_port, addr[1], serverInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 1, 0, 0, 0 )
		s.sendto(header+str(message), addr)
		print "Server sending ACK with sequence #"+ str(serverInitialSeq) + " Next sequence expectation: " + str(nextACKNumber)
		serverInitialSeq = serverInitialSeq + 1

	if(state == 3):
		header = generateHeader(src_port, addr[1], serverInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 1, 0, 0, 1 )
		s.sendto(header+str(message), addr)
		print "Server sending FIN-ACK for Client's FIN: I with sequence #"+ str(serverInitialSeq) + " Next sequence expected: " + str(nextACKNumber)
		serverInitialSeq = serverInitialSeq + 1
	if(state == 4):
		header = generateHeader(src_port, addr[1], serverInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 0, 0, 0, 1 )
		s.sendto(header+str(message), addr)
		print "Server sending FIN: J with sequence #"+ str(serverInitialSeq) + " Next sequence expected: " + str(nextACKNumber)
		serverInitialSeq = serverInitialSeq + 1
	if(state == 10):
		header = generateHeader(src_port, addr[1], serverInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 1, 1, 0, 0 )
		s.sendto(header+str(message), addr)
		print "Server sending POST/GET REQUEST ACK "+ str(serverInitialSeq) + " Next sequence expected: " + str(nextACKNumber)
		serverInitialSeq = serverInitialSeq + 1

def generateHeader(source_port = 0, dest_port = 0,sequence_number = 0,ack_number = 0,extra_header_length = 0, rwnd =0, checksum = 0, option=0, parity_bit_string =0 ,flag_ack = 0, flag_rst = 0,flag_syn =0 , flag_fin=0, message=""):
	flags_bitstring = flag_fin + (flag_syn << 1) + (flag_rst << 2) + (flag_ack << 3)
	universal_format = "!HHLLBHLLL"	
	chk = checksumFunction(message)
	complete_header = struct.pack(universal_format, source_port, dest_port, sequence_number, ack_number, flags_bitstring, rwnd, chk, option, parity_bit_string)
	return complete_header

def retransmit(s, bindport, packetWindow, firstUnackedPacket, addr, nextACKNumber):
		## Retransmit state
		header = generateHeader(bindport, addr[1], firstUnackedPacket, nextACKNumber, 0, 0, 0, 0, 0, 0, 0, 0, 0, packetWindow[firstUnackedPacket][0])
		s.sendto(header+str(packetWindow[firstUnackedPacket][0]), addr)

def updateFUP(firstUnackedPacket, ACKedPacketSequenceNumber, packetWindow):
	global serverInitialSeqCopy
	global serverInitialSeq
	global count
	if(ACKedPacketSequenceNumber == firstUnackedPacket):
		while(len(packetWindow) > 0 and packetWindow[firstUnackedPacket][1] == 1):
			del packetWindow[firstUnackedPacket]
			temp = firstUnackedPacket+DEFAULT_SENDER_WINDOW_SIZE-serverInitialSeqCopy
			if(temp < len(clientSendBuffer)):
				packetWindow[temp+serverInitialSeqCopy] = (clientSendBuffer[temp],0)
				count = 0
			firstUnackedPacket = firstUnackedPacket + 1
		return firstUnackedPacket
	return None

def resend(socket, message, address, bindport, state):
	global serverInitialSeq
	resend = True
	cnt = 0
	while(resend):
		clientSend(socket,bindport, message, address, state, 0)
		try:
			data, addr = socket.recvfrom(1500) # buffer size is 1500 bytes
			if(data != None):
				resend = False
				if(cnt > 1):
					serverInitialSeq = serverInitialSeq - 1
				return data, addr
		except:
			x = 1

def clientSend(s,src_port, message, addr, state, nextACKNumber):
	global serverInitialSeq
	if(state == 3):
		header = generateHeader(src_port, addr[1], serverInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 0, 0, 0, 0, message )
		s.sendto(header+str(message), addr)
		serverInitialSeq = serverInitialSeq + 1
	if(state == 4):
		header = generateHeader(src_port, addr[1], serverInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 1, 0, 0, 0, message )
		s.sendto(header+str(message), addr)
		print("Client Sending ACK with seq num: "+ str(serverInitialSeq))
		serverInitialSeq = serverInitialSeq + 1

def extractHeader(packetData):
	header = packetData[:27]
	header = struct.unpack("!HHLLBHLLL", header)
	headerFlags = header[4]
	headerFlags = bin(headerFlags)[2:].zfill(4)
	nextACKNumberclient = header[2] + 1
	ACKedPacketSequenceNumber = header[3]-1
	return header, headerFlags, nextACKNumberclient, ACKedPacketSequenceNumber
main()