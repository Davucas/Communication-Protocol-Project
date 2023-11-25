import rsa
from Server import generate_keys, generate_nonce, encrypt, decrypt, sign, verify, encrypt_AES, decrypt_AES
import socket
import ast
import hashlib
import select

# Client A

def protocol(public_key, private_key):
    # Send the certificate to S ( "A", "S", Ka, {N1}Ks, { H( "A", "S", Ka, {N1}Ks ) }Ka-1 )
    # Generate a nonce
    challenge = str(generate_nonce())
    # Sender 'A' and receiver 'S'
    m = "A S".encode()
    # I need the public key to be in this format so I can send it through the socket
    Ka = public_key.save_pkcs1('PEM')
    # We encrypt the nonce with S's public key
    cyphertext = encrypt(Ks, challenge)
   # This is what is going to be inside the hash for integrity
    message = m + Ka + cyphertext
    # We sign the hash with A's private key (it needs to be a str type to do that)
    signature = sign(private_key, str(message))
    # Send the message to S
    soc.send(message + signature)


    # S repplies with ( "S", "A", {N1}Ka, Ka, Kb, Kc, { H( "S", "A", {N1}Ka, Ka, Kb, Kc ) }Ks-1 )
    message = soc.recv(2048)
    sender = message[0:1].decode()
    receiver = message[2:3].decode()
    cyphertext = message[3:131]
    client_keys = ast.literal_eval(message[131:929].decode())
    signature = message[929::]
    # We save the public keys of B and C
    Kb = rsa.PublicKey.load_pkcs1(client_keys["B"], 'PEM')
    Kc = rsa.PublicKey.load_pkcs1(client_keys["C"], 'PEM')

    response = decrypt(private_key, cyphertext)

    # Verify the signature and integrity of the message
    if (verify(Ks, str(message[0:929]), signature) == False):
        raise Exception("The message has been changed")

    if (response != challenge):
        raise Exception("The message is not fresh")


    # Now A sends B and C (through S) a challenge Na
    # ( "A", "B", {Na}Kb, { H( "A", "B", {Na}Kb ) }Ka-1
    # Generate Na
    Na = str(generate_nonce())
    # We encrypt Na with B's public key
    cyphertext = encrypt(Kb, Na)
    # This is what is going to be inside the hash for integrity
    message = "A B".encode() + cyphertext
    # We sign the hash with A's private key
    signature = sign(private_key, str(message))
    soc.send(message + signature)


    # ( "A", "C", {Na}Kc, { H( "A", "C", {Na}Kc ) }Ka-1
    # We encrypt Na with C's public key
    cyphertext = encrypt(Kc, Na)
    # This is what is going to be inside the hash for integrity
    message = "A C".encode() + cyphertext
    # We sign the hash with A's private key
    signature = sign(private_key, str(message))
    soc.send(message + signature)


    # A receives the replies from B and C
    # ( "B", "A", {Na, Nb}Ka, { H( "B", "A", {Na, Nb}Ka ) }Kb-1
    # ( "C", "A", {Na, Nc}Ka, { H( "C", "A", {Na, Nc}Ka ) }Kc-1
    message = soc.recv(1024)
    sender = message[0:1].decode()
    receiver = message[2:3].decode()
    response = decrypt(private_key, message[3:131])
    signature = message[259::]

    if (response != Na):
        raise Exception("The message is not fresh")

    if (sender == "B"):
        # Verify the signature and integrity of the message
        if (verify(Kb, str(message[0:259]), signature) == False):
            raise Exception("The message has been changed")
        Nb = decrypt(private_key, message[131:259])

    elif (sender == "C"):
        if (verify(Kc, str(message[0:259]), signature) == False):
            raise Exception("The message has been changed")
        Nc = decrypt(private_key, message[131:259])


    message = soc.recv(1024)
    sender = message[0:1].decode()
    receiver = message[2:3].decode()
    response = decrypt(private_key, message[3:131])
    signature = message[259::]

    if (response != Na):
        raise Exception("The message is not fresh")

    if (sender == "B"):
        # Verify the signature and integrity of the message
        if (verify(Kb, str(message[0:259]), signature) == False):
            raise Exception("The message has been changed")
        Nb = decrypt(private_key, message[131:259])

    elif (sender == "C"):
        # Verify the signature and integrity of the message
        if (verify(Kc, str(message[0:259]), signature) == False):
            raise Exception("The message has been changed")
        Nc = decrypt(private_key, message[131:259])

    # Now A has the 3 Nonces, so it has the session key
    session_key = hashlib.sha256((Na + Nb + Nc).encode()).digest()


    # A repplies to B and C challenges
    # ( "A", "B", {Nb}Kb, { H( "A", "B", {Nb}Kb ) }Ka-1
    # We encrypt Nb with B's public key
    cyphertext = encrypt(Kb, Nb)
    # This is what is going to be inside the hash for integrity
    message = "A B".encode() + cyphertext
    # We sign the hash with A's private key
    signature = sign(private_key, str(message))
    soc.send(message + signature)


    # ( "A", "C", {Nc}Kc, { H( "A", "C", {Nc}Kc ) }Ka-1
    # We encrypt Na with C's public key
    cyphertext = encrypt(Kc, Nc)
    # This is what is going to be inside the hash for integrity
    message = "A C".encode() + cyphertext
    # We sign the hash with A's private key
    signature = sign(private_key, str(message))
    soc.send(message + signature)

    return session_key

################### Code MAIN #####################################################################
host = "127.0.0.1"
port = 6000

# Generate A's keys
(public_key, private_key) = generate_keys()

# IPv4 and TCP
soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect((host, port))
print(soc.getsockname())

# We get Ks
Ks = rsa.PublicKey.load_pkcs1(soc.recv(1024), 'PEM')

# Start the protocol
session_key = protocol(public_key, private_key)
print("The session key establishment was successful")
print("Session Key: ", session_key, "\n")

clients = ["B", "C"]

# This list is for the use of the function select
socket_list = [soc]

while True:
    print("\nSelect an option: \n 1. Send a Message \n 2. Quit \n 3. See new messages \n")
    option = input(">")

    if (option == '3'):
        # We check if there is any message received, if there is then we print it
        read_sockets = select.select(socket_list, socket_list, [])[0]
        if soc in read_sockets:
            message = soc.recv(1024)
            sender = message[0:1].decode()
            cyphertext = message[3::]
            print("\nYou have received a message from ", sender, ":")
            plaintext = decrypt_AES(session_key, cyphertext).decode()
            print("  ", plaintext, "\n")
        else:
            print("\nNo new messages")

    elif (option == '2'):
        soc.send("A quit".encode())
        soc.close()
        break

    elif (option == '1'):
        print("\nWho do you want to send a message to?:")
        receiver = input(">")
        # We make sure that the receiver exists
        while (receiver not in clients):
            print("\nERROR: ", receiver, "is not a client, try again:")
            receiver = input(">")

        print("\nEnter your message:")
        plaintext = input(">")
        m = "A " + receiver
        cyphertext = encrypt_AES(session_key, plaintext.encode())
        message = m.encode() + cyphertext
        soc.send(message)
        print("Message sent correctly")

