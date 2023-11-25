import rsa
from Server import generate_keys, generate_nonce, encrypt, decrypt, sign, verify, encrypt_AES, decrypt_AES
import socket
import ast
import hashlib
import select

# Client B

def protocol(public_key, private_key):
    # Send the certificate to S ( "B", "S", Kb, {N2}Ks, { H( "B", "S", Kb, {N2}Ks ) }Kb-1 )
    # Generate a nonce
    challenge = str(generate_nonce())
    # Sender 'B' and receiver 'S'
    m = "B S".encode()
    # I need the public key to be in this format so I can send it through the socket
    Kb = public_key.save_pkcs1('PEM')
    # We encrypt the nonce with S's public key
    cyphertext = encrypt(Ks, challenge)
   # This is what is going to be inside the hash for integrity
    message = m + Kb + cyphertext
    # We sign the hash with A's private key
    signature = sign(private_key, str(message))
    soc.send(message + signature)


    # S repplies with ( "S", "B", {N2}Kb, Ka, Kb, Kc, { H( "S", "B", {N2}Kb, Ka, Kb, Kc ) }Ks-1 )
    message = soc.recv(2048)
    sender = message[0:1].decode()
    receiver = message[2:3].decode()
    cyphertext = message[3:131]
    signature = message[929::]

    client_keys = ast.literal_eval(message[131: 929].decode())
    Ka = rsa.PublicKey.load_pkcs1(client_keys["A"], 'PEM')
    Kc = rsa.PublicKey.load_pkcs1(client_keys["C"], 'PEM')
    response = decrypt(private_key, cyphertext)

    # Verify the signature and integrity of the message
    if (verify(Ks, str(message[0:929]), signature) == False):
        raise Exception("The message has been changed")

    if (response  != challenge):
        raise Exception("The message is not fresh")


    # Receive message from A: ( "A", "B", {Na}Kb, { H( "A", "B", {Na}Kb ) }Ka-1
    message = soc.recv(1024)
    # We split the message
    sender = message[0:1].decode()
    receiver = message[2:3].decode()
    cyphertext = message[3:131]
    signature = message[131::]

    # We verify the signature and integrity of the message
    if (verify(Ka, str(message[0:131]), signature) == False):
        raise Exception("The message has been changed")

    Na = str(decrypt(private_key, cyphertext))


    # Reply to the message from A
    # ( "B", "A", {Na, Nb}Ka, { H( "B", "A", {Na, Nb}Ka ) }Kb-1
    # Generate Nb
    Nb = str(generate_nonce())
    cyphertext = encrypt(Ka, Na)
    cyphertext2 = encrypt(Ka, Nb)
    message = "B A".encode() + cyphertext + cyphertext2
    # Sign the message using b's private key
    signature = sign(private_key, str(message))

    soc.send(message + signature)


    # Receive response from A
    # ( "A", "B", {Nb}Kb, { H( "A", "B", {Nb}Kb ) }Ka-1
    message = soc.recv(1024)
    # We split the message
    sender = message[0:1].decode()
    receiver = message[2:3].decode()
    cyphertext = message[3:131]
    signature = message[131::]

    response = decrypt(private_key, cyphertext)
    # We verify the signature and integrity of the message
    if (verify(Ka, str(message[0:131]), signature) == False):
        raise Exception("The message has been changed")

    if (response  != Nb):
        raise Exception("The message is not fresh")


    # B sends C a challenge using the nonce Nb
    # ( "B", "C", {Nb}Kc, { H( "B", "C", {Nb}Kc ) }Kb-1
    cyphertext = encrypt(Kc, Nb)
    message = "B C".encode() + cyphertext
    signature = sign(private_key, str(message))
    soc.send(message + signature)


    # B receives repply from C
    # ( "C", "B", {Nb}Kb, {Nc}Kb, { H( "C", "B", {Nb}Kb, {Nc}Kb ) }Kc-1
    message = soc.recv(1024)
    # We split the message
    sender = message[0:1].decode()
    receiver = message[2:3].decode()
    cyphertext = message[3:131]
    signature = message[259::]

    response = decrypt(private_key, cyphertext)
    # We verify the signature and integrity of the message
    if (verify(Kc, str(message[0:259]), signature) == False):
        raise Exception("The message has been changed")

    if (response != Nb):
        raise Exception("The message is not fresh")

    Nc = decrypt(private_key, message[131:259])


    # Now B also has the three nonces, so it has the session key
    session_key = hashlib.sha256((Na + Nb + Nc).encode()).digest()


    # Finally B replies to C's challenge and the protocol finsishes
    # ( "B", "C", {Nc}Kc, { H( "B", "C", {Nc}Kc ) }Kb-1
    cyphertext = encrypt(Kc, Nc)
    message = "B C".encode() + cyphertext
    signature = sign(private_key, str(message))
    soc.send(message + signature)



    return session_key

################### Code MAIN #####################################################################
host = "127.0.0.1"
port = 6000

# Generate B's keys
(public_key, private_key) = generate_keys()

# IPv4 and TCP
soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect((host, port))
print(soc.getsockname())

Ks = rsa.PublicKey.load_pkcs1(soc.recv(1024), 'PEM')

# Start the protocol
session_key = protocol(public_key, private_key)
print("The session key establishment was successful")
print("Session Key: ", session_key, "\n")


# Once the conection is established and the session key is agreed, we can start sending messages
# Do an infinite loop where you can write the messages to send

clients = ["A", "C"]

# This list is fot the use of the function select
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
        soc.send("B quit".encode())
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
        m = "B " + receiver
        cyphertext = encrypt_AES(session_key, plaintext.encode())
        message = m.encode() + cyphertext
        soc.send(message)
        print("Message sent correctly")




