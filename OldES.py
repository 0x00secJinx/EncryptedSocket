"""
Module used to encrypt/decrypt the data being sent and recv'd from sockets
"""

import socket
import sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


class EncryptedSocket(object):

    """
    Create a class that uses the socket module with the crypto module
    to encrypt/decrypt data
    """

    sock = None
    passw = None

    def set_passw(self, passw):

        """
        set the password for the EncryptedSocket class
        """

        self.passw = passw

    def get_passw(self):

        """
        Return the class password if it was set
        """

        if self.passw is not None:
            return self.passw
        else:
            print("No password was set")
            return -1

    def create_socket(self, sock_family, sock_type):

        """
        Method to create the socket
        """

        if self.sock is None:
            self.sock = socket.socket(sock_family, sock_type)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def send_data(self, data):

        """
        Method to send data through the encrypt method and send the results
        This method is overridden in the EncryptedServerSocket class to send
            data over the accepted client socket
        """

        self.sock.send(self.encrypt(data))

    def recv_data(self):

        """
        Method to receive data and pass the data into the decrypt method
        Returns a string with the padding (from the encryption method) removed
        """

        data = b""
        while True:
            recv_buffer = self.sock.recv(1024)
            data += recv_buffer
            if len(recv_buffer) < 1024:
                break

        return self.decrypt(data).strip()

    def encrypt(self, data):

        """
        Method to encrypt data with the set password
        """

        chunksize = 64 * 1024

        if self.passw is not None:
            hasher = SHA256.new(self.passw.encode('utf-8'))
            hashed_pass = hasher.digest()
        else:
            print("No password was set\nUse the set_passw(passw) method in the\
                    Encrypted Socket class")
            sys.exit(1)

        init_vec = Random.new().read(16)
        aes_cipher = AES.new(hashed_pass, AES.MODE_CBC, init_vec)
        encrypted_data = b""

        chnks = [data[i:i + chunksize] for i in range(0, len(data), chunksize)]

        for chunk in chnks:
            if len(chunk) % 16 != 0:
                chunk += " " * (16 - (len(chunk) % 16))

            encrypted_data += aes_cipher.encrypt(chunk)

        return (init_vec + encrypted_data)

    def decrypt(self, data):

        """
        Method to decrypt data with the set password
        """

        chunksize = 64 * 1024

        if self.passw is not None:
            hasher = SHA256.new(self.passw.encode('utf-8'))
            hashed_pass = hasher.digest()
        else:
            print("No password was set\nUse the set_passw(passw) method in the\
                     EncryptedSocket class")
            sys.exit(1)

        init_vec = data[:16]
        data = data[16:]
        aes_cipher = AES.new(hashed_pass, AES.MODE_CBC, init_vec)
        decrypted_data = b""

        chnks = [data[i:i + chunksize] for i in range(0, len(data), chunksize)]

        for chunk in chnks:
            if len(chunk) % 16 != 0:
                chunk += " " * (16 - (len(chunk) % 16))

            decrypted_data += aes_cipher.decrypt(chunk)

        try:
            return decrypted_data.decode('utf-8')
        except socket.error as excp:
            print("Socket error was caught: %s" % excp)
            self.close_socket()
            sys.exit(-1)
        except RuntimeWarning as excp:
            print("Error was caught: %s" % excp)
            self.close_socket()
            sys.exit(-1)

    def close_socket(self):

        """
        Close the open sockets
        Overridden in EncryptedServerSocket class
        """

        self.sock.close()


class EncryptedServerSocket(EncryptedSocket):

    """
    Class that expands on EncryptedSocket with socket server functions
        (listen, accept, bind...)
    """

    client_sock = None
    client_addr = None

    def listen_for_cons(self):

        """
        Method to listen for incoming connections
        """

        self.sock.listen(5)

    def accept_conns(self):

        """
        Accept incoming connections
        """

        con, addr = self.sock.accept()
        self.client_sock = con
        self.client_addr = addr

    def bind_socket(self, host, port):

        """
        Bind socket to specified address and port
        """

        self.sock.bind((host, int(port)))

    def send_data(self, data):

        """
        Send data after it has been encrypted
        Overrides the parent 'send_data' method as to send the data
            through the client socket
        """

        try:
            self.client_sock.send(self.encrypt(data))
        except socket.error as excp:
            print("Error: %s" % excp)
            self.close_socket()
            sys.exit(-1)

    def recv_data(self):

        """
        Receive data and decrypt
        Overrides the parent 'recv_data' method to recv data from
            the client socket
        """

        data = b""
        while True:
            recv_buffer = self.client_sock.recv(1024)
            data += recv_buffer
            if len(recv_buffer) < 1024:
                break

        return self.decrypt(data).strip()

    def close_socket(self):

        """
        Close both socket (client and server)
        Overrides the parent 'close_socket' method to close the client socket
            and the listening socket
        """

        #print("Server close method")
        self.client_sock.close()
        self.sock.close()


class EncryptedClientSocket(EncryptedSocket):

    """
    Class that expands on EncryptedSocket with client socket functions
        (connect)
    """

    def connect_to_server(self, host, port):

        """
        Connect to the specified host
        """

        try:
            self.sock.connect((host, int(port)))
            # print("Connected to server")
        except socket.error as excp:
            print("Error: %s" % excp)
            sys.exit(-1)
