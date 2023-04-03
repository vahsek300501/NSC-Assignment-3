import socket
from RSA import RSA
from gmpy2 import mpz
from hashlib import sha256
import time
from threading import Thread
import random 

rsaKeys = RSA()
clientPublicKey , clientPrivateKey = rsaKeys.generatePublicPrivateKeys(85809553255734121337984567446462131854492783534608490864158858150208843819531,74106102163014752691484349649710860403934207211599628367037366169409413906871)
pkdaPublicKey = (mpz(65537), mpz(76116193208345101514389967868140081547072814053409908279442639814681461496300740445029422748676318383851399121480251774669133736818633260078826563066105570807769614913001307794763424359843678935208060885096080943604014059619123553202413276635104734808930589181325783704720570720426132205095615793784840968801))
clientID = "client2"

def registerClientPublicKeyToPKDA():
    global rsaKeys, pkdaPublicKey
    print("Registering public key with PKDA in secure Mannar")
    host = "127.0.0.1"
    port = 8000
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # connect to server on local computer
    s.connect((host,port))

    textInput = "ACCEPT_"+clientID+"_"+str(clientPublicKey[0])+"_"+str(clientPublicKey[1])
    hmac = sha256(textInput.encode()).hexdigest()
    integralHMAC = rsaKeys.convertTextToNumbers(hmac)
    signedHMAC = rsaKeys.encrypt(integralHMAC,pkdaPublicKey)

    sendingMessage = textInput+"_"+str(signedHMAC)
    s.send(sendingMessage.encode('utf-8'))    
    serverResult = s.recv(1024)
    print("PKDA Response: "+str(serverResult.decode('utf-8')))
    print()
    s.close()

def requestForKey(clientRequestID,messageNumber):
    global rsaKeys, pkdaPublicKey
    host = "127.0.0.1"
    port = 8000
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((host,port))

    textInput = "REQUEST_"+clientID+"_"+clientRequestID+"_"+str(time.time())
    s.send(textInput.encode("utf-8"))
    receivedResponse = s.recv(6144)
    receivedResponse = receivedResponse.decode('utf-8')
    receivedResponseList = receivedResponse.split("_")

    publicKeyClientExponent = mpz(receivedResponseList[1])
    publicKeyClientModulus = mpz(receivedResponseList[2])

    encryptedHMAC = mpz(receivedResponseList[4])
    decryptedHMAC = rsaKeys.decrypt(encryptedHMAC,pkdaPublicKey)
    hmacAscii = rsaKeys.convertNumberToText(decryptedHMAC)

    print("["+messageNumber+"] Generating HMAC")
    generatorString = str(receivedResponseList[0])+"_"+str(receivedResponseList[1])+"_"+str(receivedResponseList[2])+"_"+str(receivedResponseList[3])
    generatedHMAC = sha256(generatorString.encode()).hexdigest()
    print("["+messageNumber+"] Verifying HMAC")
    if hmacAscii == generatedHMAC:
        print("["+messageNumber+"] HMAC verifies that the message has been sent by PKDA")
        return publicKeyClientExponent, publicKeyClientModulus
    else:
        print("["+messageNumber+"] HMAC verification failed")
    return None, None

def serveClient(clientFileDescriptor,clientAddress):
    print("Connection Received from: "+str(clientAddress))
    print()
    print("[Message-1] Connection initiation handshake from client")

    message = clientFileDescriptor.recv(6144)
    message = message.decode('utf-8')
    initiationMessageList = message.split("_")
    encryptedMessage = mpz(initiationMessageList[0])
    hmac = initiationMessageList[1]
    decryptedMessage = rsaKeys.decrypt(encryptedMessage,clientPrivateKey)
    
    decryptedMessageAscii = rsaKeys.convertNumberToText(decryptedMessage)
    generatedHMAC = sha256(decryptedMessageAscii.encode()).hexdigest()

    senderIdentifier = decryptedMessageAscii.split("_")[0]
    senderNonce = decryptedMessageAscii.split("_")[1]
    print("[Message-1] Sender Identification: "+str(senderIdentifier))
    print("[Message-1] Verifying message integrity from sender")
    if generatedHMAC == hmac:
        print("[Message-1] HMAC verified")
    
    elif generatedHMAC != hmac:
        print("[Message-1] Message has been tampered")
        return False

    print()
    print("[Message-2] Requesting PKDA for public key of "+str(senderIdentifier))
    publicKeyClientExponent,publicKeyClientModulus = requestForKey(senderIdentifier,"Message-2")
    print()

    print("[Message-3] Sending N1||N2 encrypted with public key of "+senderIdentifier)
    nonce = random.randint(1,100)
    sendingMessageNonce = str(senderNonce)+"_"+str(nonce)
    encryptedSendingNonce = str(rsaKeys.encrypt(rsaKeys.convertTextToNumbers(sendingMessageNonce),(publicKeyClientExponent,publicKeyClientModulus)))
    clientFileDescriptor.send(encryptedSendingNonce.encode('utf-8'))
    print()

    print("[Message-4] Receiving encrypted N2")
    receivedNonce2 = clientFileDescriptor.recv(6144)
    decryptedNonce2Ascii = rsaKeys.convertNumberToText(rsaKeys.decrypt(mpz(receivedNonce2.decode('utf-8')),clientPrivateKey))
    print("[Message-4] Verifying Nonce")
    if str(decryptedNonce2Ascii) == str(nonce):
        print("[Message-4] Nonce Verified")
    else:
        print("[Message-4] Nonce not verified")
        return

    print()
    print("Authentication Complete with "+senderIdentifier+". We can send and receive message in encrypted manner")
    print()

    while(True):

        print("Receiving Encrypted Message")
        receivedMessage = clientFileDescriptor.recv(6144)
        receivedMessage = receivedMessage.decode('utf-8')
        receivedMessageHMAC = receivedMessage.split("_")[1]
        receivedMessage = receivedMessage.split("_")[0]
        print("Encrypted Message: "+str(receivedMessage))
        decryptedMessage = rsaKeys.convertNumberToText(rsaKeys.decrypt(mpz(receivedMessage),clientPrivateKey))
        print("Verifying HMAC")
        if sha256(decryptedMessage.encode()).hexdigest() == receivedMessageHMAC:
            print("HMAC Verified for the message")
            print("Message in plain text: "+str(decryptedMessage))
        else:
            print("HMAC verification failed")
            print("Message has been tampered with")
        print()

        print("Enter a message to send to "+senderIdentifier)
        tmp = input()
        sendingMessageHMAC = sha256(tmp.encode()).hexdigest()
        sendingMessage = str(rsaKeys.encrypt(mpz(rsaKeys.convertTextToNumbers(tmp)),(publicKeyClientExponent,publicKeyClientModulus)))
        sendingMessage = sendingMessage + "_" + sendingMessageHMAC
        clientFileDescriptor.send(sendingMessage.encode('utf-8'))
        print()

def Main():
    registerClientPublicKeyToPKDA()
    
    host = ""
    port = 6000
    
    print("Client2 started at port: "+str(port))
    # Creating a socket
    clientSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # Binding to host and port
    clientSocket.bind((host,port))
    # Listening to client in parallel
    clientSocket.listen(10)

    while(True):
        print("Listening for incomming connections")
        clientFileDecriptor, clientAddress = clientSocket.accept() 
        newClientThread = Thread(target=serveClient, args = [clientFileDecriptor,clientAddress])
        newClientThread.start()
Main()