#!/usr/bin/python3.5 -B
"""
Script to test the EncryptedSocket server class
"""

import socket
import sys
sys.path.insert(0, "../")
import EncryptedSocket


def main():

    """
    Make the Encrypted server class and test the class
    """

    server = EncryptedSocket.EncryptedServerSocket()
    server.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    server.set_passw("test")
    server.bind_socket("", 15000)
    server.listen_for_conns()
    server.accept_conns()
    server.send_data("This is a test from Server")
    print(server.recv_data())

if __name__ == '__main__':
    main()
