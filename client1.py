import socket
from RSA import RSA
import gmpy2
from gmpy2 import mpz
from hashlib import sha256
import time
import secrets
import pdb

rsaKeys = RSA()
clientPublicKey , clientPrivateKey = rsaKeys.generatePublicPrivateKeys(103060327266338343317492429736872291197733584335510785579403277606918763322133,83884794256337772654104091915147011229294495322086170285763007751312952160721)
pkdaPublicKey = (mpz(65537), mpz(76116193208345101514389967868140081547072814053409908279442639814681461496300740445029422748676318383851399121480251774669133736818633260078826563066105570807769614913001307794763424359843678935208060885096080943604014059619123553202413276635104734808930589181325783704720570720426132205095615793784840968801))
clientID = "client1"

def registerClientPublicKeyToPKDA():
    print("Registering the client to PKDA in secure manner")
    global rsaKeys, pkdaPublicKey
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
    print(serverResult.decode('utf-8'))
    print()
    s.close()

def requestForKey(clientRequestID):
    print("Requesting for keys of client with ID: "+clientRequestID)
    global rsaKeys, pkdaPublicKey
    host = "127.0.0.1"
    port = 8000
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 
    # connect to server on local computer
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

    print("Generating HMAC")
    generatorString = str(receivedResponseList[0])+"_"+str(receivedResponseList[1])+"_"+str(receivedResponseList[2])+"_"+str(receivedResponseList[3])
    generatedHMAC = sha256(generatorString.encode()).hexdigest()
    print("Verifying HMAC")
    if hmacAscii == generatedHMAC:
        print("HMAC verifies that the message has been sent by PKDA")
        print()
        return publicKeyClientExponent, publicKeyClientModulus
    else:
        print("HMAC verification failed")
        print()
    return None, None

def communicateWithOtherClient(requestedClientID,clientExponent,clientModulus):
    host = "127.0.0.1"
    port = 6000
    fd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 
    # connect to server on local computer
    fd.connect((host,port))


    nonce = 100
    message = clientID+"_"+str(nonce)
    hmac = sha256(message.encode()).hexdigest()
    messageIntegers = rsaKeys.convertTextToNumbers(message)
    encryptedMessage = rsaKeys.encrypt(messageIntegers,(clientExponent,clientModulus))
    sendingInitiationMessage = str(encryptedMessage)+"_"+str(hmac)
    fd.send(sendingInitiationMessage.encode('utf-8'))
    
    receivedMessage = fd.recv(6144)
    encryptedNonce = mpz(receivedMessage.decode('utf-8'))
    decryptedNonce = rsaKeys.decrypt(encryptedNonce,clientPrivateKey)
    decryptedNonceAscii = rsaKeys.convertNumberToText(decryptedNonce)
    receivedNonce1 = decryptedNonceAscii.split("_")[0]
    receivedNonce2 = decryptedNonceAscii.split("_")[1]
    
    print("Verifying received nonce 1")
    if str(receivedNonce1) == str(nonce):
        print("Received Nonce verified")
    else:
        print("Nonce verification failed")
        return
    
    print("Final Handshake message: sending N2 encrypted by public key of client2")
    encryptedReceivedNonce2 = str(rsaKeys.encrypt(mpz(rsaKeys.convertTextToNumbers(str(receivedNonce2))),(clientExponent,clientModulus)))
    fd.send(encryptedReceivedNonce2.encode('utf-8'))

    print()
    print("Authentication Complete")
    print("Sending messages now")
    print()
    print()

    while(True):
        print("Enter the message to send to other client")
        tmp = input()
        sendingMessage = str(rsaKeys.encrypt(mpz(rsaKeys.convertTextToNumbers(tmp)),(clientExponent,clientModulus)))
        fd.send(sendingMessage.encode('utf-8'))
        print()
        receivedMessage = fd.recv(6144)
        receivedMessage = receivedMessage.decode('utf-8')
        print("Encrypted Received Message")
        print(receivedMessage)
        print()
        print("Decrypted Message")
        decryptedMessage = rsaKeys.convertNumberToText(rsaKeys.decrypt(mpz(receivedMessage),clientPrivateKey))
        print(str(decryptedMessage))

def Main():
    registerClientPublicKeyToPKDA()
    exponent,modulus = requestForKey("client2")
    print(exponent)
    print(modulus)
    print()
    print()
    communicateWithOtherClient('client2',exponent,modulus)

print("Public Key client: ")
print(clientPublicKey)
print()
print()
print("Private Key client: ")
print(clientPrivateKey)
Main()