import os
import sys

def main():
	if len(sys.argv) < 4:
		usage()
	udpPort = sys.argv[1]
	ip = sys.argv[2]
	netEmuPort = sys.argv[3]
	os.system('python server.py -s '+ udpPort)

def usage():
	sys.stdout = sys.stderr
	print 'Usage: python FxA-server.py [UDP port] [IP] [NetEmu port]'
	print '[maximum window segment size]'
	sys.exit(2)

main()
