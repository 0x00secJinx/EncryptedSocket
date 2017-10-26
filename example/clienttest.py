#!/usr/bin/python3.5 -B
"""
Script to test the EncryptedSocket client class
"""

import socket
import EncryptedSocket


def main():

    """
    Make the Encrypted client class and test the class
    """

    client = EncryptedSocket.EncryptedClientSocket()
    client.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    client.set_passw("test")
    client.connect_to_server("localhost", 15000)
    print(client.recv_data())
    client.send_data("This is a test from Client")
    client.close_socket()

if __name__ == '__main__':
    main()
