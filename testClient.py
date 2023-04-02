import socket
from RSA import RSA
import gmpy2
from gmpy2 import mpz
from hashlib import sha256
import time

rsaKeys = RSA()
clientPublicKey , clientPrivateKey = rsaKeys.generatePublicPrivateKeys(15830291231451036113,10047854401552475231)
pkdaPublicKey = (mpz(65537), mpz(76116193208345101514389967868140081547072814053409908279442639814681461496300740445029422748676318383851399121480251774669133736818633260078826563066105570807769614913001307794763424359843678935208060885096080943604014059619123553202413276635104734808930589181325783704720570720426132205095615793784840968801))
clientID = "client1"
def registerClientPublicKeyToPKDA():
    global rsaKeys, pkdaPublicKey
    host = "127.0.0.1"
    port = 8000
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 
    # connect to server on local computer
    s.connect((host,port))
    textInput = "ACCEPT_"+clientID+"_"+str(clientPublicKey[0])+"_"+str(clientPublicKey[1])
    hmac = sha256(textInput.encode()).hexdigest()
    integralHMAC = rsaKeys.convertTextToNumbers(hmac)
    print("HMAC: "+str(hmac))
    signedHMAC = rsaKeys.encrypt(integralHMAC,pkdaPublicKey)
    print("Signed HMAC: "+str(signedHMAC))
    sendingMessage = textInput+"_"+str(signedHMAC)
    s.send(sendingMessage.encode('utf-8'))    
    serverResult = s.recv(1024)
    print(serverResult.decode('utf-8'))
    s.close()

def requestForKey(clientRequestID):
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
        return publicKeyClientExponent, publicKeyClientModulus
    else:
        print("HMAC verification failed")
    return None, None
    

def Main():
    registerClientPublicKeyToPKDA()
    exponent,modulus = requestForKey(clientID)
    print(exponent)
    print(modulus)

print("Public Key client: ")
print(clientPublicKey)
print()
print()
print("Private Key client: ")
print(clientPrivateKey)
Main()