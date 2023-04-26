import socket, sys
from struct import *
from AddressParser import get_host_by_addr


HOST_ADDRESS = "192.168.1.100"  # The server's hostname or IP address
HOST_PORT = 65432  # The port used by the server


#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet */
try:
	s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except (socket.error , msg):
	print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
	sys.exit()

# receive a packet
while True:
	packet = s.recvfrom(65565)
	
	#packet string from tuple
	packet = packet[0]
	
	#parse ethernet header
	eth_length = 14
	
	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH' , eth_header)
	eth_protocol = socket.ntohs(eth[2])

	#Parse IP packets, IP Protocol number = 8
	if eth_protocol == 8 :
		#Parse IP header
		#take first 20 characters for the ip header
		ip_header = packet[eth_length:20+eth_length]
		
		#now unpack them :)
		iph = unpack('!BBHHHBBH4s4s' , ip_header)

		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF

		iph_length = ihl * 4

		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);

		#TCP protocol
		if protocol == 6 :
			t = iph_length + eth_length
			tcp_header = packet[t:t+20]

			#now unpack them :)
			tcph = unpack('!HHLLBBHHH' , tcp_header)
			
			source_port = tcph[0]
			dest_port = tcph[1]
			
			if source_port == HOST_PORT or dest_port == HOST_PORT or s_addr == HOST_ADDRESS or d_addr == HOST_ADDRESS:
				continue
			
			sequence = tcph[2]
			acknowledgement = tcph[3]
			doff_reserved = tcph[4]
			tcph_length = doff_reserved >> 4
			
			message = ""
			message += 'Destination MAC : ' + str(packet[0:6]) + ' Source MAC : ' + str(packet[6:12]) + ' Protocol : ' + str(eth_protocol) + '\n'
			
			message += 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)  + '\n'
			
			message += "Source host address:" + str(get_host_by_addr(s_addr)) + '\n'
			
			message += 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
			
			print(message)
			
			h_size = eth_length + iph_length + tcph_length * 4
			data_size = len(packet) - h_size
			
			#get data from the packet
			data = str(packet[h_size:])
			
			#print ('Data : ' + data)

			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
				s2.connect((HOST_ADDRESS, HOST_PORT))
				s2.sendall(str.encode(message))
