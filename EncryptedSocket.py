
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
		with open(self.priv_file, "rb") as priv:
			self.priv_key = serialization.load_pem_private_key(priv.read(), password=None, backend=default_backend())
		with open(self.pub_file, "rb") as pub:
			self.pub_key_bytes = pub.read()


	def get_peer_key(self):
		
		self.peer_pub = serialization.load_pem_public_key(self.s.recv(4096), default_backend())

	def send_pub_key(self):

		self.s.send(self.pub_key_bytes)

	def connect(self, serv_addr):
		if not self.server:
			self.s.connect(serv_addr)
			self.exchange_keys()
		else:
			raise RuntimeError("connect cannot be called when class is created with server=True")


	def listen(self, backlog):
		if self.server:
			self.s.listen(backlog)
		else:
			raise RuntimeError("listen function requires the class to be defined with server=True")

	def accept(self):
		if self.server:
			conn, addr = self.s.accept()
			enc_conn = EncryptedSocket(conn, self.priv_file, self.pub_file, server=True)
			enc_conn.load_keys()
			enc_conn.exchange_keys()
			return enc_conn
		else:
			raise RuntimeError("accept function requires the class to be defined with server=True")

	def bind(self, bind_addr):
		if self.server:
			self.s.bind(bind_addr)
		else:
			raise RuntimeError("bind function requires the class to be defined with server=True")

	def exchange_keys(self):
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

	def encrypt_data(self, data):
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
		iv = data[:16]
		data = data[16:]
		cipher = Cipher(algorithms.AES(self.shared_secret), modes.CBC(iv), backend=default_backend())
		decryptor = cipher.decryptor()
		plain_text = decryptor.update(data) + decryptor.finalize()
		return plain_text

	def send_data(self, data):
		self.s.send(self.encrypt_data(data))

	def recv_data(self, length):
		return self.decrypt_data(self.s.recv(length))

	def close(self):
		self.s.close()

	def add_padding(self, data):
		if (len(data) % 16 != 0):
			data = data + " " * (16 - (len(data) % 16))

		return data