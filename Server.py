import secrets
import rsa
import socket
import threading
from threading import Thread
from Crypto.Cipher import AES


def generate_keys():
    (public_key, private_key) = rsa.newkeys(1024)
    return public_key, private_key

def encrypt(key, message):
    return rsa.encrypt(message.encode('utf8'), key)

def decrypt(key, message):
    try:
        return rsa.decrypt(message, key).decode('utf8')
    except:
        return False

def generate_nonce():
    return secrets.randbits(128)

def sign(key, message):
    return rsa.sign(message.encode('ascii'), key, 'SHA-1')

def verify(key, message, signature):
    try:
        return rsa.verify(message.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return False

def encrypt_AES(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    return cipher.nonce + tag + ciphertext

def decrypt_AES (key, message):
    nonce = message[:AES.block_size]
    tag = message[AES.block_size:AES.block_size * 2]
    ciphertext = message[AES.block_size * 2:]

    cipher = AES.new(key, AES.MODE_EAX, nonce)

    return cipher.decrypt_and_verify(ciphertext, tag)



def main():
    host = "127.0.0.1"
    port = 6000

    # We need to encode it because it needs to be a byte type to be able to send it with the socket
    Ks = public_key.save_pkcs1('PEM')

    # IPv4 and TCP
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket successfully created")
    soc.bind((host, port))
    soc.listen(2)
    print("Socket listening")

    while True:
        c, addr = soc.accept()
        print("Connected to", addr)

        # For the implementation I added this step where S sends everyone that connects to the socket his publicKey
        # I did this because the clients and the server don't share space in memory, so they don't share the global variables
        c.send(Ks)
        # We need one thread to 'talk' to each client
        Thread(target=client_thread, args=(c, addr)).start()


    #soc.close()



def client_thread(client, addr):
    global count
    global semaphore
    global semaphore1

    # Receive the certificate from the client
    mutex.acquire()
    message = client.recv(1024)
    mutex.release()

    # We split the message to read it
    sender = message[0:1].decode()
    receiver = message[2:3].decode()
    key_bytes = message[3:254]
    cyphertext = message[254:382]
    signature = message[382::]

    mutex.acquire()
    # We store the public client_key, the client address and the client in the global variables
    clients_keys[sender] = key_bytes
    clients_address[sender] = addr
    clients[sender] = client
    # We use this so the 3 threads have to wait until all of them have done this before doing the next step
    count += 1
    if (count < 3):
        cond.wait()
    else:
        count = 0
        cond.notify_all()
    mutex.release()

    nonce = str(decrypt(private_key, cyphertext))
    # This is the client key in the form of a key object, this is the one we will be using
    client_key = rsa.PublicKey.load_pkcs1(key_bytes)

    # We verify the signature and integrity of the message
    if (verify(client_key, str(message[0:382]), signature) == False):
        raise Exception("The message has been changed")


    # Repply to the message sending back the nonces, and sending the public keys
    # ( "S", "A", {N1}Ka, Ka, Kb, Kc, { H( "S", "A", {N1}Ka ) }Ks-1 )
    m = "S " + sender
    # We encrypt with the client public key that we just received
    e = encrypt(client_key, nonce)
    m = m.encode() + e + str(clients_keys).encode()
    s = sign(private_key, str(m))

    mutex.acquire()
    client.send(m + s)
    count += 1
    if (count < 3):
        cond.wait()
    else:
        count = 0
        cond.notify_all()
    mutex.release()


    if ( clients_address["A"] == addr ):
        # In this part because only A is executing this and we are using the semaphore to make B and C wait
        # we don't need to use the mutex
        # ( "A", "B", {Na}Kb, { H( "A", "B", {Na}Kb ) }Ka-1
        message = client.recv(1024)
        # S is not able to read the rest of the message so there is no point in saving all of it in variables
        receiver = message[2:3].decode()
        # We send the message to the receiver
        clients[receiver].send(message)

        # ( "A", "C", {Na}Kc, { H( "A", "C", {Na}Kc ) }Ka-1
        message = client.recv(1024)
        receiver = message[2:3].decode()
        # We send the message to the receiver
        clients[receiver].send(message)

        # Now B and C can do the next step
        semaphore.release()

        """ We need to wait until A repplies to the messages that B and C sent, that implies
         that the messages have to be sent to A before this is executed. That's why se use again the condition variable"""
        # ( "A", "B", {Nb}Kb, { H( "A", "B", {Nb}Kb ) }Ka-1
        mutex.acquire()
        if (count < 2):
            cond.wait()
        message = client.recv(1024)
        mutex.release()

        receiver = message[2:3].decode()
        clients[receiver].send(message)


        # ( "A", "C", {Nc}Kc, { H( "A", "B", {Nc}Kc ) }Ka-1
        mutex.acquire()
        message = client.recv(1024)
        mutex.release()

        receiver = message[2:3].decode()
        clients[receiver].send(message)

        # Now A doesn't need to do anything else

    else:
        # The semaphore is initialised to 0, so B and C will be blocked until S has sent the message from A to B and C
        semaphore.acquire()
        semaphore.release()

        # We receive the messages from B and C and we send them to A
        # ( "B", "A", {Na, Nb}Ka, { H( "B", "A", {Na, Nb}Ka ) }Kb-1
        # ( "C", "A", {Na, Nc}Ka, { H( "C", "A", {Na, Nc}Ka ) }Kc-1
        mutex.acquire()
        message = client.recv(1024)
        mutex.release()

        receiver = message[2:3].decode()
        # We send the message to the receiver
        mutex.acquire()
        clients[receiver].send(message)
        # We use the condition variable to synchronize B and C with A
        count += 1
        if (count <2):
            cond.wait()
        else:
            count = 0
            cond.notify_all()
        mutex.release()


        if (clients_address["B"] == addr):
            # ( "B", "C", {Nb}Kc, { H( "B", "C", {Nb}Kc ) }Kb-1
            message = client.recv(1024)
            receiver = message[2:3].decode()
            # We send the message to the receiver
            clients[receiver].send(message)

            semaphore1.release()

            # Now we use the same trick with the semaphore to block B until C is done
            semaphore.acquire()
            message = client.recv(1024)
            receiver = message[2:3].decode()
            # We send the message to the receiver
            clients[receiver].send(message)


        else:
            # C needs to wait until B has sent him the message, so we use the semaphore again initalised at 0
            semaphore1.acquire()
            # ( "C", "B", {Nb}Kb, {Nc}Kb, { H( "C", "B", {Nb}Kb, {Nc}Kabc ) }Kc-1
            message = client.recv(1024)
            receiver = message[2:3].decode()
            # We send the message to the receiver
            clients[receiver].send(message)

            semaphore1.release()
            # Now we let B do the next step
            semaphore.release()

    safe_chat(client)



def safe_chat(client):
    """Once the protocol has finished this is just a safe chat were every message is encrypted with the
        session key that has been established by the protocol"""
    while True:

        message = client.recv(1024)

        # If a client quits it sends a message like 'A quit', so we can close the socket and remove them from clients
        if (message[2::] == "quit".encode()):
            clients.pop(message.decode()[0])
            client.close()
            break

        sender = message[0:1].decode()
        receiver = message[2:3].decode()

        # Check if the receiver is still connected before sending the message
        if (receiver not in clients):
            print("The client", receiver, "is not available")
        else:
            # We send the message to the receiver
            clients[receiver].send(message)
            print("Message from ", sender, " received and sent to ", receiver, "\n")
            print(message)



# Global variables

# We will store the public keys of the clients here, each client will be assigned to his key
clients_keys = {}
clients_address = {}
clients = {}

# Use mutex to ensure only one thread access to the socket or the global variables at the same time
mutex = threading.Lock()
"""
Use the condition variable to ensure that when all the threads have to do the same no thread is doing the next step
of the protocol until all of them have finished the previous one. For example when before sending to all the clients
the dictionary with all the public keys we need to make sure all of them have been received 
"""
cond = threading.Condition(mutex)
count = 0
"""
We use the semaphore for the same purpose, but when the threads are not doing the same job. For example when B and C
need to wait until A has sent the messages to S and S has sent them back to B and C
"""
semaphore = threading.Semaphore(0)
semaphore1 = threading.Semaphore(0)

# S's keys
(public_key, private_key) = generate_keys()



if __name__ == '__main__':
    main()
