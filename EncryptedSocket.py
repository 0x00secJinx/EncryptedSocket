
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import socket
import sys

class EncryptedSocket(object):
	def __init__(self, sock, privkey_file, pubkey_file, server=False):
		self.s = sock
		self.priv_file = privkey_file
		self.pub_file = pubkey_file
		self.priv_key = None
		self.pub_key_bytes = None
		self.peer_pub = None
		self.shared_secret = None
		self.server = server
		self.encrypter = None


	def load_keys(self):

		"""
		@function 
			load_keys

		@params
			@ self - the EncryptedSocket class

		@description
			load the private and public key pair from the provided files for the class
			these keys will be used to find a shared secret between the peers
		"""

		with open(self.priv_file, "rb") as priv:
			self.priv_key = serialization.load_pem_private_key(priv.read(), password=None, backend=default_backend())
		with open(self.pub_file, "rb") as pub:
			self.pub_key_bytes = pub.read()


	def get_peer_key(self):

		"""
		@function
			get_peer_key

		@params
			@ self - The EncryptedSocket class

		@description
			set the received data to the self.peer_pub class variable
			The user should not call this function as it is used for
			the exchange_keys function
		"""
		
		self.peer_pub = serialization.load_pem_public_key(self.s.recv(4096), default_backend())

	def send_pub_key(self):

		"""
		@function
			send_pub_key

		@params
			@ self - The EncryptedSocket class

		@decription
			send the public key bytes to the peer
			users should not call this function as it is used for
			the exchange_keys function
		"""

		self.s.send(self.pub_key_bytes)

	def connect(self, serv_addr):

		"""
		@function
			connect

		@params
			@ self - The EncryptedSocket class
			@ serv_addr - a tuple containing the server's ip address
						  and the port to connect to. Just like the 
						  socket module connect parameters. (eg. ("github.com", 80))

		@description
			connect to the server using the address given
			If the class was specified with server=True,
			this function will raise a RuntimeError
		"""

		if not self.server:
			self.s.connect(serv_addr)
			self.exchange_keys()
		else:
			raise RuntimeError("connect cannot be called when class is created with server=True")


	def listen(self, backlog):

		"""
		@function
			listen

		@params
			@ self - The EncryptedSocket class
			@ backlog - 

		@description
			calls the listen function on the socket provided to the class
			if the class was initilized with server=False the function
			will raise a RuntimeError as clients do not need to call the
			listen function
		"""

		if self.server:
			self.s.listen(backlog)
		else:
			raise RuntimeError("listen function requires the class to be defined with server=True")

	def accept(self):

		"""
		@function
			accept

		@params
			@ self - The EncryptedSocket class

		@description
			calls the accept function on the provided socket and creates a 
			new EncryptedSocket class with the client socket. The key file from
			the parent class are used and the server parameter is set to True as
			this is the socket the server will use to communicate with the client
			The server will then exchange keys with the client to get their shared
			secret to use for communication

			If the class was initialized with server=False the function will raise a
			RuntimeError as the client does not need to call the accept function

		@returns
			A new EncryptedSocket class to communicate with the client
		"""

		if self.server:
			conn, addr = self.s.accept()
			enc_conn = EncryptedSocket(conn, self.priv_file, self.pub_file, server=True)
			enc_conn.load_keys()
			enc_conn.exchange_keys()
			return enc_conn
		else:
			raise RuntimeError("accept function requires the class to be defined with server=True")

	def bind(self, bind_addr):

		"""
		@function
			bind

		@params
			@self - The EncryptedSocket class
			@bind_addr - A tuple containing the address for the socket to bind to
						 
		@description
			Directly calls the bind() function on the provided socket and passes
			the exact tuple passed to the function. (Subject to change)

			If the class was initialized with server=False the function will raise
			a RuntimeError as the client should not call the bind function
		"""

		if self.server:
			self.s.bind(bind_addr)
		else:
			raise RuntimeError("bind function requires the class to be defined with server=True")

	def exchange_keys(self):

		"""
		@function
			exchange_keys

		@params
			@self - The EncryptedSocket class

		@description
			Use Elliptical Curve Diffie-Hellman key exchange to get a shared
			secret to use for encrypting and decrypting data. Once the shared
			secret is derived, store it in the class's self.shared_secret variable
		"""

		if self.server:
			self.send_pub_key()
			self.get_peer_key()
		else:
			self.get_peer_key()
			self.send_pub_key()
		shared_key = self.priv_key.exchange(ec.ECDH(), self.peer_pub)
		derived_key = HKDF(
			algorithm=hashes.SHA256(),
			length=32,
			salt=None,
			info=b'handshake data',
			backend=default_backend()).derive(shared_key)
		self.shared_secret = derived_key


	def generate_new_keys(self):

		"""
		@function
			generate_new_keys

		@params
			@self - The EncryptedSocket class

		@description
			This function generates a 384-bit ECC private key and the
			corresponding public key and serializes the data and saves
			them in the files passed into the class
		"""

		with open(self.priv_file, "wb") as priv_file:
			p = ec.generate_private_key(ec.SECP384R1(), default_backend())
			pem = p.private_bytes(encoding=serialization.Encoding.PEM,
								  format=serialization.PrivateFormat.TraditionalOpenSSL,
								  encryption_algorithm=serialization.NoEncryption())
			priv_file.write(pem)
		with open(self.pub_file, "wb") as pub_file:
			pub = p.public_key()
			pemp = pub.public_bytes(encoding=serialization.Encoding.PEM,
								   format=serialization.PublicFormat.SubjectPublicKeyInfo)
			pub_file.write(pemp)

	def close(self):

		"""
		@function
			close

		@params
			@self - The EncryptedSocket class

		@description
			The function calls the close() method for the socket passed to 
			the class
		"""

		self.s.close()

	def encrypt_data(self, data):

		"""
		@function
			encrypt_data

		@params
			@ self - The EncryptedSocket class
			@ data - The data string to encrypt

		@description
			Take the data passed in the data param and encrypt it
			using AES with the shared secret. The IV is prepended
			to the data to make it available to the peer
			This method returns the cipher text of the data.
		"""

		iv = os.urandom(16)
		data = self.add_padding(data)
		try:
			data = data.encode('UTF-8')
		except AttributeError:
			pass
		cipher = Cipher(algorithms.AES(self.shared_secret), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		cipher_text = encryptor.update(data) + encryptor.finalize()
		cipher_text = iv + cipher_text
		return cipher_text

	def decrypt_data(self, data):

		"""
		@function
			decrypt_data

		@param
			@ self - The EncryptedSocket class
			@ data - The bytes to decrypt

		@description
			Take the bytes passed and decrypt them using AES with the
			shared key. The iv is spliced from the data sent. This 
			method returns the plain text of the data
		"""

		iv = data[:16]
		data = data[16:]
		cipher = Cipher(algorithms.AES(self.shared_secret), modes.CBC(iv), backend=default_backend())
		decryptor = cipher.decryptor()
		plain_text = decryptor.update(data) + decryptor.finalize()
		return plain_text

	def send_data(self, data):

		"""
		@function
			send_data

		@params
			@ self - The EncryptedSocket class
			@ data - The data to send through the socket
					 Data is encoded to bytes

		@description
			The data passed as parameter is encoded to bytes then encrypted
			then sent to the peer
		"""

		self.s.send(self.encrypt_data(data))

	def recv_data(self, length):

		"""
		@function
			recv_data

		@params
			@self - The EncryptedSocket class
			@length - the amount of bytes to recv from the socket

		@description
			The function calls the recv function on the socket with the
			specified length. The data is then decoded and returned
		"""
		
		return self.decrypt_data(self.s.recv(length))

	def add_padding(self, data):

		"""
		@function
			add_padding

		@params
			@ self - The EncryptedSocket class
			@ data - The data to add padding to

		@description
			This function takes data and adds spaces to make sure
			the length is a multiple of 16. AES requires block
			sizes and 16 is our block size
		"""

		if (len(data) % 16 != 0):
			data = data + " " * (16 - (len(data) % 16))

		return data
