import sys
from socket import *
import random
import struct
import rsa
import time
import os


ECHO_PORT = 50000 + 7
BUFSIZE = 1500
#initialize client and server with random sequence numbers.
clientInitialSeq = int(random.random()*10000)
clientInitialSeqCopy = clientInitialSeq + 2 ## 2 for SYN SYN-ACK compensation
serverInitialSeq = int(random.random()*10000)
DEFAULT_SENDER_WINDOW_SIZE = 5
clientSendBuffer = []
count = 0
clientRecieveBuffer = {}
DEFAULT_TIMEOUT_VALUE = 2
functionFlag = True ## True means receive
clientReceiveBufferSize = 0
fl = True
x = 0

def main():
	global functionFlag
	if len(sys.argv) < 3:
		usage()
	if sys.argv[1] == '-c':
		client()
	else:
		usage()

def usage():
	sys.stdout = sys.stderr
	print 'Usage: udpecho -s [port] (server)'
	print 'or:    udpecho -c bindport desthost [destport] <file (client)'
	sys.exit(2)


def resend(socket, message, address, bindport, state):
	global clientInitialSeq
	resend = True
	cnt = 0
	while(resend):
		clientSend(socket,bindport, message, address, state, 0)
		cnt += 1

		try:
			data, addr = socket.recvfrom(1500) # buffer size is 1500 bytes
			if(data != None):
				resend = False
				return data, addr
		except:
			if(cnt>=1):
				clientInitialSeq = clientInitialSeq - 1

def client():
	global DEFAULT_TIMEOUT_VALUE
	global clientInitialSeq
	global clientSendBuffer
	global count
	global clientReceiveBufferSize
	global fl
	global clientInitialSeqCopy
	clientInitialSeqCopy = clientInitialSeqCopy + 1
	global x
	## dictionary of sequence numbers mapped to message+
	packetWindow = {}

	(cpub_key, cpriv_key) = rsa.newkeys(512)
	if len(sys.argv) < 4:
		usage()
	bindport = eval(sys.argv[2])
	host = sys.argv[3]
	if len(sys.argv) > 4:
		port = eval(sys.argv[4])
	else:
		port = ECHO_PORT
	addr = host, port
	s = socket(AF_INET, SOCK_DGRAM)
	s.bind(('', bindport))
	print 'RxP client ready'

	initializeConn = True
	flag = True
	finalConn = False

	print "Available commands: \n connect"
	print "Enter Command"
	connectionCommand = raw_input()
	if(connectionCommand == 'connect'):
		while 1:
			if(initializeConn):
				MESSAGE = 'request connection'
				secret = None
				try:
					s.setblocking(1)
					s.settimeout(DEFAULT_TIMEOUT_VALUE)
					#initial SYN sent to server
					#secret and address recieved from the Server
					serverPubKey, addr = resend(s, MESSAGE, addr, bindport, 1)
					header, headerFlags, nextACKNumberclient, ACKedPacketSequenceNumber = extractHeader(serverPubKey)
					if(flag):
						print "Syn Ack + Public Key received from server at "+ str(addr) +"\n"
					if(headerFlags[0] == '1' and headerFlags[2] == '1'): #SYN ACK from server received
						MESSAGE = cpub_key
						finalAck, addr = resend(s, MESSAGE, addr, bindport, 2)
					if(flag):
						print "Final Connection Establishment ACK received! from server at " + str(addr) +"\n"
					initializeConn = False
				except:
					if(flag):
						print 'Request timeout... trying again...\n'
						sys.exit()
			else:
				## method to get message to put in packet
				if(fl):
					if(x==0):
						print "Available commands: \nget <filename> \npost <filename> \ndisconnect"
						print "Enter Command"
						x = 1
					else:
						print "Available commands:\ndisconnect"
						print "Enter Command"
					tempInput = raw_input().split()
					if(tempInput[0].lower() == 'post'):
						functionFlag = False
						## read in file
						f = open(tempInput[1], 'r')
						## convert file to string
						fileString = ""
						lines = f.readlines()
						for line in lines:
							fileString = fileString + line
						f.close()
						## store in packet ready sizes of maximum 1473 bytes
						i = 0
						while(i < len(fileString)-1436):
							clientSendBuffer.append(fileString[i:i+1436])
							i = i + 1436
						clientSendBuffer.append(fileString[i:])
						## initializing client window with default window size
						initialPacketWindowIndex = 0
						while(initialPacketWindowIndex < DEFAULT_SENDER_WINDOW_SIZE and initialPacketWindowIndex < len(clientSendBuffer)):
							packetWindow[clientInitialSeqCopy+initialPacketWindowIndex] = (clientSendBuffer[initialPacketWindowIndex],0)
							initialPacketWindowIndex = initialPacketWindowIndex + 1

					elif(tempInput[0].lower() == 'get'):
						functionFlag = True
					elif(tempInput[0].lower() == 'disconnect'):
						finalConn = True
						fl=False
					else:
						print "Command not supported, disconnecting..."
						finalConn = True
						fl=False

				MESSAGE = "closing request"
				if(finalConn):
					print "Terminating connection..."
					s.setblocking(1)
					s.settimeout(DEFAULT_TIMEOUT_VALUE)
					try:
						# Fin: I sent to server
						finalAck, addr = resend(s, MESSAGE, addr, bindport, 5)
						header, headerFlags, nextACKNumberclient, ACKedPacketSequenceNumber = extractHeader(finalAck)
						if(headerFlags[0] == '1' and headerFlags[2] == '0' and headerFlags[3] == '1'): #ACK for FIN 1
							print("Client Received Fin I ACK")
							s.settimeout(None)
							serverFin, addr = s.recvfrom(1500)
							header, headerFlags, nextACKNumberclient, ACKedPacketSequenceNumber = extractHeader(serverFin)
							if(headerFlags[3] == '1' and headerFlags[0] == '0'):
								print("Client Received Server Fin: J")
								MESSAGE = "sending final server FIN's Ack"
								clientSend(s,bindport, MESSAGE, addr, 6, 0)
								s.setblocking(1)
								s.settimeout(3)
								currentTime = time.time()
								while(time.time() < currentTime + 6):
									try:
										serverFin, addr = s.recvfrom(1500)
										MESSAGE = "sending final server FIN's Ack"
										time.sleep(2)
										clientSend(s,bindport, MESSAGE, addr, 6, 0)	
									except:
										print "timed wait....terminating connection..."
										break
								break
					except:
						print 'Request timeout....trying again..\n'
						#Max number of tries = 5 reached. Exit.
						sys.exit()
				## Normal message exchange
				else:
					if(not functionFlag):
						print("Client transmitting packets now...")
						clientInitialSeq = clientInitialSeqCopy
						current = clientInitialSeq
						firstUnackedPacket = clientInitialSeq
						while(1):
							try:
								MESSAGE = "post"
								s.setblocking(1)
								s.settimeout(DEFAULT_TIMEOUT_VALUE)
								clientInitialSeq = clientInitialSeq - 1
								serverPubKey, addr = resend(s, MESSAGE, addr, bindport, 7)
								header, headerFlags, nextACKNumberclient, ACKedPacketSequenceNumber = extractHeader(serverPubKey)
								if(headerFlags[1] == '1' and headerFlags[0] == '1'):
									clientReceiveBufferSize = int(serverPubKey[27:])
									print "RECEIVED POST COMMAND CONFIRMATION ACK"
									break
							except:
								if(flag):
									print 'Request timeout... trying again!!!!..\n'
						
						print("Client Ready to receive file now...")
						while(current < clientInitialSeqCopy+len(clientSendBuffer) and not finalConn):
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
								print "No ACK received...sending other packets in window..."
							current = current + 1
							clientInitialSeq = current
							if(count >= DEFAULT_SENDER_WINDOW_SIZE or len(packetWindow) < DEFAULT_SENDER_WINDOW_SIZE):
								s.setblocking(1)
								s.settimeout(DEFAULT_TIMEOUT_VALUE)
								retransmitBool = True
								while(retransmitBool):
									try:
										serverACK, addr = s.recvfrom(1500)
										header, headerFlags, nextACKNumberclient, ACKedPacketSequenceNumber = extractHeader(serverACK)		
										if(ACKedPacketSequenceNumber < clientInitialSeqCopy+len(clientSendBuffer)):				
											packetWindow[ACKedPacketSequenceNumber] = (packetWindow[ACKedPacketSequenceNumber][0],1)
										update = updateFUP(firstUnackedPacket, ACKedPacketSequenceNumber, packetWindow)
										print "ACK RECEIVED for sequence #" + str(ACKedPacketSequenceNumber)
										if(update != None):
											current = update
											firstUnackedPacket = update
											retransmitBool = False
											clientInitialSeq = firstUnackedPacket
										if(len(packetWindow)==0):
											finalConn=True
											break
									except:
										print "ACK not received....retransmitting packet with sequence #" + str(firstUnackedPacket)
										retransmit(s,bindport,packetWindow, firstUnackedPacket, addr, 0)
					elif(functionFlag):
						print "Client initialized for GET"
						global clientRecieveBuffer
						while(1):
							try:
								MESSAGE = "get"+tempInput[1]
								s.setblocking(1)
								s.settimeout(DEFAULT_TIMEOUT_VALUE)
								serverPubKey, addr = resend(s, MESSAGE, addr, bindport, 7)
								header, headerFlags, nextACKNumberclient, ACKedPacketSequenceNumber = extractHeader(serverPubKey)
								if(headerFlags[1] == '1' and headerFlags[0] == '1'):
									clientReceiveBufferSize = int(serverPubKey[27:])
									print "RECEIVED GET CONFIRMATION ACK"
									break
							except:
								if(flag):
									print 'Request timeout....trying again!!!!..\n'
						print("Client Ready to receive file now")
						while(1):
							s.settimeout(None)
							data, addr = s.recvfrom(BUFSIZE)
							header = data[:27]
							header = struct.unpack("!HHLLBHLLL", header)
							headerFlags = header[4]
							headerFlags = bin(headerFlags)[2:].zfill(4)
							nextACKNumberserver = header[2] + 1 ##SYN number + 1
							chksum = header[6]
							if(str(checksumFunction(data[27:])) == str(chksum)):
								MESSAGE = "Ack"
								if(not header[2] in clientRecieveBuffer):
									clientRecieveBuffer[header[2]] = data[27:]
								serverSend(s,port,MESSAGE,addr,2, nextACKNumberserver)
							else:
								print "DID NOT MATCH CHECKSUM"
							if(len(clientRecieveBuffer) == clientReceiveBufferSize):
								print "File Transfer Complete, waiting for command now..."
								break
						createClientFile(clientRecieveBuffer)
					finalConn = True

def createClientFile(buffer):
	fileString = ""
	for k in sorted(clientRecieveBuffer.keys()):
		fileString = fileString + clientRecieveBuffer[k]
	f = open("clientReceivedFile.txt",'w')
	f.write(fileString)
	f.close()

def retransmit(s, bindport, packetWindow, firstUnackedPacket, addr, nextACKNumber):
		## Retransmit state
		header = generateHeader(bindport, addr[1], firstUnackedPacket, nextACKNumber, 0, 0, 0, 0, 0, 0, 0, 0, 0, packetWindow[firstUnackedPacket][0])
		s.sendto(header+str(packetWindow[firstUnackedPacket][0]), addr)
		print("Client re-transmitting packet with sequence #"+ str(firstUnackedPacket))

def extractHeader(packetData):
	header = packetData[:27]
	header = struct.unpack("!HHLLBHLLL", header)
	headerFlags = header[4]
	headerFlags = bin(headerFlags)[2:].zfill(4)
	nextACKNumberclient = header[2] + 1
	ACKedPacketSequenceNumber = header[3]-1
	return header, headerFlags, nextACKNumberclient, ACKedPacketSequenceNumber

def updateFUP(firstUnackedPacket, ACKedPacketSequenceNumber, packetWindow):
	global clientInitialSeqCopy
	global clientSendBuffer
	global count
	if(ACKedPacketSequenceNumber == firstUnackedPacket):
		while(len(packetWindow) > 0 and packetWindow[firstUnackedPacket][1] == 1):
			del packetWindow[firstUnackedPacket]
			temp = firstUnackedPacket+DEFAULT_SENDER_WINDOW_SIZE-clientInitialSeqCopy
			if(temp < len(clientSendBuffer)):
				packetWindow[temp+clientInitialSeqCopy] = (clientSendBuffer[temp],0)
				count = 0
			firstUnackedPacket = firstUnackedPacket + 1
		return firstUnackedPacket
	return None

def checksumFunction(message):
	retVal = 0
	message = str(message)
	for ch in message:
		retVal = (retVal>>1) + ((retVal & 1) << 31)
		retVal += ord(ch)
		retVal &= 0xffffffff
	return retVal

def generateHeader(source_port = 0, dest_port = 0,sequence_number = 0,ack_number = 0,extra_header_length = 0, rwnd =0, checksum = 0, option=0, parity_bit_string =0 ,flag_ack = 0, flag_rst = 0,flag_syn =0 , flag_fin=0, message=""):
	flags_bitstring = flag_fin + (flag_syn << 1) + (flag_rst << 2) + (flag_ack << 3)
	universal_format = "!HHLLBHLLL"	
	chk = checksumFunction(message)
	complete_header = struct.pack(universal_format, source_port, dest_port, sequence_number, ack_number, flags_bitstring, rwnd, chk, option, parity_bit_string)
	return complete_header

def clientSend(s,src_port, message, addr, state, nextACKNumber):
	global clientInitialSeq
	if(state == 1): ##initial SYN
		header = generateHeader(src_port, addr[1], clientInitialSeq, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, message )
		s.sendto(header+str(message), addr)
		print "client sending initial SYN with sequence #"+ str(clientInitialSeq)
		clientInitialSeq = clientInitialSeq + 1
	if(state == 2): ##SYN ACK sent to server
		header = generateHeader(src_port, addr[1], clientInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 1, 0, 1, 0, message )
		s.sendto(header+str(message), addr)
		print "client sent public key to server with sequence #"+str(clientInitialSeq)
		clientInitialSeq = clientInitialSeq + 1
	if(state == 3):
		header = generateHeader(src_port, addr[1], clientInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 0, 0, 0, 0, message )
		s.sendto(header+str(message), addr)
		print("Client Sending Message with sequence #"+ str(clientInitialSeq))
		clientInitialSeq = clientInitialSeq + 1
	if(state == 4):
		header = generateHeader(src_port, addr[1], clientInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 1, 0, 0, 0, message )
		s.sendto(header+str(message), addr)
		print("Client Sending ACK with sequence #"+ str(clientInitialSeq))
		clientInitialSeq = clientInitialSeq + 1
	if(state == 5):
		header = generateHeader(src_port, addr[1], clientInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 0, 0, 0, 1, message )
		s.sendto(header+str(message), addr)
		print("Client Sending Fin: I with sequence #"+ str(clientInitialSeq))
		clientInitialSeq = clientInitialSeq + 1
	if(state == 6):
		header = generateHeader(src_port, addr[1], clientInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 1, 0, 0, 1, message )
		s.sendto(header+str(message), addr)
		print("Client Sending Fin: J's ACK with sequence #"+ str(clientInitialSeq))
		clientInitialSeq = clientInitialSeq + 1
	if(state == 7):
		header = generateHeader(src_port, addr[1], clientInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 0, 1, 0, 0, message )
		s.sendto(header+str(message), addr)
		print("Client sending GET/POST request with sequence #"+ str(clientInitialSeq))
		clientInitialSeq = clientInitialSeq + 1


def serverSend(s,src_port, message, addr, state, nextACKNumber = 0):
	global clientInitialSeq
	if(state == 2):
		header = generateHeader(src_port, addr[1], clientInitialSeq, nextACKNumber, 0, 0, 0, 0, 0, 1, 0, 0, 0 )
		s.sendto(header+str(message), addr)
		print "Client sending ACK with sequence #"+ str(clientInitialSeq) + " Next sequence expectation: " + str(nextACKNumber)
		clientInitialSeq = clientInitialSeq + 1
		
main()