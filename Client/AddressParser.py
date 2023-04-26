import socket
import sys


def get_host_by_addr(address):
	try:
		host = socket.gethostbyaddr(address)
		return host
	except:
		return "host indefined"
