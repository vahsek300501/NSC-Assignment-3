import socket
from RSA import RSA
from threading import Thread, Lock
from hashlib import sha256
import gmpy2
from gmpy2 import mpz
import pdb

clientPublicKeyMap = {}
rsaKey = RSA()
publicKey, privateKey = rsaKey.generatePublicPrivateKeys(11315021318077988822297698686245966994073231987629388711704681996437996088725429632461707272214616976409354431392925248076618696111389609344054891397490343,
                                                         6727003959482992676938581203928184232372129737758591272654595917870502706042256578008832342305931486750526418300360050790528820785214228675264283482234807)


def decryptMessages(cipherText):
    global privateKey, rsaKey
    return rsaKey.decrypt(mpz(cipherText), privateKey)

def getNewClientPublicKey(requestMessage,clientID,publicKeyExponent, publicKeyModulus,hmac):
    global clientPublicKeyMap, rsaKey
    print("[Client Public Key Registration Request] clientID: "+str(clientID))
    unsignedHMAC = decryptMessages(hmac)
    unsignedHMACAscii = rsaKey.convertNumberToText(unsignedHMAC)
    generatedHMAC = sha256((requestMessage+"_"+clientID+"_"+publicKeyExponent+"_"+publicKeyModulus).encode()).hexdigest()
    print("Verifying HMAC")
    if unsignedHMACAscii == generatedHMAC:
        print("HMAC verification is done")
        print("Client Added succesfully")
        print()
        clientPublicKeyMap[clientID] = [publicKeyExponent,publicKeyModulus]
        return True
    return False

def serveClientRequest(clientID,clientRequestID,timestamp):
    # pdb.set_trace()
    global clientPublicKeyMap, rsaKey, publicKey, privateKey
    print("[Client Public key request] clientID: "+str(clientID)+" clientRequestedID: "+str(clientRequestID)+" timestamp: "+str(timestamp))
    requestedPublicKeyExponent = clientPublicKeyMap[clientRequestID][0]
    requestedPublicKeyModulus = clientPublicKeyMap[clientRequestID][1]

    responseString = clientRequestID+"_"+str(requestedPublicKeyExponent)+"_"+str(requestedPublicKeyModulus)+"_"+str(timestamp)

    hashedResponseString = sha256(responseString.encode('utf-8')).hexdigest()
    integralHash = rsaKey.convertTextToNumbers(hashedResponseString)
    encryptedHash = rsaKey.encrypt(mpz(integralHash),privateKey)
    print(encryptedHash)
    sendingString = str(responseString)+"_"+str(encryptedHash)
    return sendingString

def processClientRequest(clientSocket, clientAddress, mutexLock):
    global clientPublicKeyMap, publicKey, privateKey
    mutexLock.acquire()
    while(True):
        clientData = clientSocket.recv(6144)
        clientData = clientData.decode('utf-8')
        if not clientData:
            break
        clientDataList = clientData.split("_")
        if clientDataList[0] == 'ACCEPT':
            result = getNewClientPublicKey(clientDataList[0],clientDataList[1],clientDataList[2],clientDataList[3],clientDataList[4])
            if result:
                clientSocket.send("accepted".encode('utf-8'))
            else:
                clientSocket.send("rejected".encode('utf-8'))

        
        if clientDataList[0] == 'REQUEST':
            sendingString = serveClientRequest(clientDataList[1],clientDataList[2],clientDataList[3])
            clientSocket.send(sendingString.encode('utf-8'))

    mutexLock.release()


def Main():
    host = ""
    port = 8000
    mutexLock = Lock()
    
    # Creating a socket
    serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # Binding to host and port
    serverSocket.bind((host,port))
    # Listening to client in parallel
    serverSocket.listen(10)

    

    while(True):
        
        clientSocket, clientAddress = serverSocket.accept()
        print(clientAddress)
        newClientThread = Thread(target=processClientRequest,args=[clientSocket,clientAddress,mutexLock])
        newClientThread.start()


print("Public key: ")
print(publicKey)
Main()

