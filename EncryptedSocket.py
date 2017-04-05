import socket
import struct
import sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


# Class for an encrypted socket
class EncryptedSocket:

	# Class variables for the socket and password
	SOCK = None
	PASSW = None

	# Set the password for the encryption and decryption methods
	def set_passw(self, passw):
		self.PASSW = passw

	# Return the password that was set
	def get_passw(self):
		if self.PASSW is not None:
			return self.PASSW
		else:
			print("No password was set")
			return -1

	# Method for creation of a socket
	def create_socket(self, sock_family, sock_type):
		if self.SOCK is None:
			self.SOCK = socket.socket(sock_family, sock_type)
			self.SOCK.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	# Method to send data through the encrypt method and send the results
	# Overridden in the EncryptedServerSocket to send over the accepted client sock
	def send_data(self, data):
		self.SOCK.send(self.encrypt(data))

	# Method to receive data and pass the data into the decrypt method
	# Returns a string with the padding (from the encryption method) removed
	def recv_data(self):
		data = b""
		while True:
			buffer = self.SOCK.recv(1024)
			data += buffer
			if len(buffer) < 1024:
				break

		return self.decrypt(data).strip()

	# Method to encrypt data with the set password
	def encrypt(self, data):

		chunksize = 64 * 1024

		if self.PASSW is not None:
			hasher = SHA256.new(self.PASSW.encode('utf-8'))
			hashed_pass = hasher.digest()
		else:
			print("No password was set\nUse the set_passw(passw) method in the Encrypted Socket class")
			sys.exit(1)

		iv = Random.new().read(16)
		aes_cipher = AES.new(hashed_pass, AES.MODE_CBC, iv)
		encrypted_data = b""

		chunks = [data[i:i+chunksize] for i in range(0, len(data), chunksize)]

		for chunk in chunks:
			if len(chunk) % 16 != 0:
				chunk += " " * (16 - (len(chunk) % 16))

			encrypted_data += aes_cipher.encrypt(chunk)

		return (iv + encrypted_data)

	def decrypt(self, data):

		chunksize = 64 * 1024

		if self.PASSW is not None:
			hasher = SHA256.new(self.PASSW.encode('utf-8'))
			hashed_pass = hasher.digest()
		else:
			print("No password was set\nUse the set_passw(passw) method in the EncryptedSocket class")
			sys.exit(1)

		iv = data[:16]
		data = data[16:]
		#print(len(iv))
		aes_cipher = AES.new(hashed_pass, AES.MODE_CBC, iv)
		decrypted_data = b""

		chunks = [data[i:i+chunksize] for i in range(0, len(data), chunksize)]

		for chunk in chunks:
			if len(chunk) % 16 != 0:
				chunk += " " * (16 - (len(chunk) % 16))

			decrypted_data += aes_cipher.decrypt(chunk)

		try:
			return decrypted_data.decode('utf-8')
		except Exception as e:
			print("Error: %s" % e)
			self.close_socket()
			sys.exit(-1)

	# Overridden in EncryptedServerSocket class
	def close_socket(self):
		print("Socket close method")
		self.SOCK.close()


class EncryptedServerSocket(EncryptedSocket):

	CLIENT_SOCK = None

	def listen_for_conns(self):
		self.SOCK.listen(5)

	def accept_conns(self):
		con, addr = self.SOCK.accept()
		self.CLIENT_SOCK = con

	def bind_socket(self, port):
		self.SOCK.bind(("", int(port)))

	def send_data(self, data):
		try:
			self.CLIENT_SOCK.send(self.encrypt(data))
		except Exception as e:
			print("Error: %s" % e)

	def recv_data(self):
		data = b""
		while True:
			buffer = self.CLIENT_SOCK.recv(1024)
			data += buffer
			if len(buffer) < 1024:
				break

		return self.decrypt(data).strip()

	def close_socket(self):
		print("Server close method")
		self.CLIENT_SOCK.close()
		self.SOCK.close()

class EncryptedClientSocket(EncryptedSocket):

	def connect_to_server(self, host, port):
		try:
			self.SOCK.connect((host, int(port)))
			#print("Connected to server")
		except Exception as e:
			print("Error: %s" % e)
