# Communication-Protocol-Project
This is a project I did for a class where I had to implement a protocol for a chat server between 3 clients that guaranteed authentication, confidentiality and integrity. The requirements were:
- The 3 clients must set a mutually agreed session key, but they can't communicate with each other directly (only through the server).
- There must be end-to-end encryption (i.e the server can't read the messages).
- The protocol must guarantee confidentiality, authentication and integrity

### Description of the Protocol (step by step)
1. Clients A, B and C send their certificates to the server S, sending at the same time a challenge (a nonce) which should be encrypted with S’s public key for confidentiality using RSA. The message should be hashed using the SHA-1 algorithm and the hash should be digitally signed using the client’s private key, this is to provide integrity and authentication.
2. S receives the messages and verifies the authentication (by checking the digital signature) and the integrity (by hashing the message with the same hashing algorithm and comparing it to the hash sent by the client). S decrypts the message (using his private key) and replies to the challenge by sending back the same nonce (encrypted with the corresponding client public key for confidentiality). S also sends each client the public keys of the other clients, so that everyone knows everyone else's public key. All of these should be provided with integrity and digitally signed (again using the hash algorithm and S’s private key to sign it).
3. Clients A, B and C receive S messages and check the integrity and authentication, and the response to the challenge (by comparing the nonce received to the one they sent). Now the client A sends B and C a challenge with a new nonce (this is the nonce Na, that will be used for generating the session key later). This message should be encrypted for confidentiality with the receiver public key and provided with integrity and authentication. The message will be sent through S (but S shouldn’t be able to see the nonce).
4. Clients B and C receive the message and check the integrity and authentication. They reply to the challenge by sending back the nonce Na, and send their own challenge (Nb and Nc). All of this should be encrypted for confidentiality with A’s public key and provided with integrity and authentication. Again, the message will be sent through S but S shouldn’t be able to see its content (S should only be able to see who are the sender and the receiver).
5. Client A receives the messages and checks the authentication and integrity. And now A has the three nonces for generating the session key. A reply to B and C challenges sending back Nb and Nc respectively. The message should be encrypted with the receiver public key for confidentiality and provided with integrity and authentication. As always, the message will be sent through S, but S shouldn’t be able to see its content.
6. Clients B and C check the integrity and authentication of the message sent by A and check the nonce. Now B send a message to C with the challenge Nb encrypted with C’s public key for confidentiality and provided with authentication and integrity. The message is sent through S.
7. Client C receives the message and checks the authentication and the integrity. Now C should know the three nonces Na, Nb and Nc (so he should have the session key). C replies to the challenge sending back Nb encrypted with the session key Kabc for confidentiality and sends his own challenge Nc encrypted with B’s public key for confidentiality. The message should be provided with integrity and authentication as always (hashing the message and digitally signing it with C’s private key). The message will be sent through S.
8. Finally, the client B will receive the message and check its authentication, integrity, and response to the challenge (he has received Nc so B should know the session key now). Now B replies to C’s challenge by sending back Nc encrypted with the session key and provided with authentication and integrity. The message will be sent through S.
9. Now every client should know the session key (hashing the combination of the three nonces, using SHA256) and all communications should be encrypted using the session key and the AES protocol. Also, all communications will be sent through the server S (that shouldn’t be able to read the content).

Note: For the implementation I had to split some of these steps into several, since some steps send several messages at the same time (for example, in step 3 A sends two messages at the same time) or some other steps required an intermediate step (send message to S and S forwards it). But I decided not to split them for the description because is easier to understand how the protocol works.

### Diagram:

![image](https://github.com/Davucas/Communication-Protocol-Project/assets/40278318/5de62756-913d-4934-bb72-3506bb43aefa)


![image](https://github.com/Davucas/Communication-Protocol-Project/assets/40278318/cf8696a7-fd59-45b6-a179-50ad5f2b0cef)


![image](https://github.com/Davucas/Communication-Protocol-Project/assets/40278318/066cabd1-39c1-46eb-98da-093785b760d2)


![image](https://github.com/Davucas/Communication-Protocol-Project/assets/40278318/4fd1b053-f79e-453e-abb4-1fb98d75222c)




_**NOTATION:**_

![image](https://github.com/Davucas/Communication-Protocol-Project/assets/40278318/a1885e20-1d2b-42fd-87d9-d676a5b21941)


### Protocol design
Confidentiality is provided by the encryption of the messages, every critical information in a message is encrypted by the sender with the receiver’s public key so no one else (not even S) can read it. Then the protocol also provides authentication and integrity by hashing the message and signing it with a digital signature. Then the receiver will always verify the integrity by hashing the original message with the same function and comparing it to the hash sent and signed.
The mutually agreed setup is provided by the three nonces (Na, Nb and Nc) that are shared by the three entities and then they are concatenated and hashed with SHA256 to generate the new session key. These nonces are not known by the server S.
All the communications sent in the protocol always have the same format:

![image](https://github.com/Davucas/Communication-Protocol-Project/assets/40278318/034eb211-3127-45a2-a461-584f13daa304)

Where message 1 is optional and is only used if the information been sent doesn’t need to be provided with confidentiality. If the message (or part of it) needs to be provided with confidentiality, then message 2 is used. This format allows the server to know who the sender and the receiver are, and if needed some extra information placed in message 1, but it doesn’t allow S or anyone else to read its content. This format as explained above also provides integrity by hashing all the message and authentication by signing that hash.
