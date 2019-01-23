
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import socket
import sys

class EncryptedSocket(object):
	def __init__(self, sock, privkey_file, server=False):
		self.s = sock
		self.priv_file = privkey_file
		self.priv_key = None
		self.pub_key = None
		self.peer_pub = None
		self.shared_secret = None
		self.server = server
		self.encrypter = None

		with open(self.priv_file, "rb") as priv:
			self.priv_key = serialization.load_pem_private_key(priv.read(), password=None, backend=default_backend())
		self.pub_key = self.priv_key.public_key()


	def get_peer_key(self):
		
		self.peer_pub = self.s.recv(4096)

	def send_pub_key(self):

		self.s.send(self.pub_key)

	def connect(self, serv_addr):
		if not self.server:
			self.s.connect(serv_addr)
			self.exchange_keys()
			raise RuntimeError("connect cannot be called when class is created with server=True")


	def listen(self, backlog):
		if self.server:
			self.s.listen(backlog)
		else:
			raise RuntimeError("listen function requires the class to be defined with server=True")

	def accept(self):
		if self.server:
			conn, addr = self.s.accept()
			enc_conn = EncryptedSocket(conn, self.priv_file, server=True)
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
		n_priv_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
		self.pub_key = n_priv_key.public_key()
		if self.server:
			self.send_pub_key()
			self.get_peer_key()
		else:
			self.get_peer_key()
			self.send_pub_key()
		shared_key = n_priv_key.exchange(ec.ECDH(), self.peer_pub)
		self.shared_secret = HKDF(
			algorithm=hashes.SHA256(),
			length=32,
			salt=None,
			info=b'handshake data',
			backend=default_backend()).derive(shared_key)

		self.encrypter = Fernet(self.shared_secret)

	def generate_new_keys(self):
		with open(self.privkey_file, "wb") as priv_file:
			p = ec.generate_private_key(ec.SECP348R1(), default_backend())
			pem = p.private_bytes(encoding=serialization.Encoding.PEM,
								  format=serialization.PrivateFormat.TraditionalOpenSSL,
								  encryption_algorithm=serialization.NoEncryption())
			priv_file.write(pem)

	def send(self, data):
		self.s.send(self.encrypter.encrypt(data.encode('UTF-8')))

	def recv(self, length):
		return self.encrypter.decrypt(self.s.recv(length))
