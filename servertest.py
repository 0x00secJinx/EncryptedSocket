#!/usr/bin/env python
import socket
from EncryptedSocket import EncryptedSocket

def main():
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s = EncryptedSocket(sock, "priv.pem", "pub.pem", server=True)
	s.generate_new_keys()
	s.load_keys()
	s.bind(("", 8025))
	s.listen(5)
	print("Bound to port 8025")
	while True:
		conn = s.accept()
		conn.close()
		s.close()


if __name__ == '__main__':
	main()