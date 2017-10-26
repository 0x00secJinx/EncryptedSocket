# EncryptedSocket
A few python3.5 classes that encrypt data before sending with a set password

To install:
    from the directory of the module, run
    `pip3.5 install .`
    This will install the module in the python3.5
        dist-package directory

To use:
	- Simply "import EncryptedSocket"

Documentation:
    Make and config the socket:
    Client:
        `
        client = EncryptedSocket.EncryptedClientSocket()
        client.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        client.set_passw("[password]")
        client.connect_to_server("[host]", [port])
        `