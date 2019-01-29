#!/usr/bin/env python
import socket 
from EncryptedSocket import EncryptedSocket

def main():
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s = EncryptedSocket(sock, "cli_priv.pem", "cli_pub.pem")
	s.generate_new_keys()
	s.load_keys()
	s.connect(("", 8025))
	s.send_data("This is test data")
	data = s.recv_data(4096)
	print(data)
	s.close()

if __name__ == '__main__':
	main()