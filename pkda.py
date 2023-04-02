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
    global clientPublicKeyMap
    unsignedHMAC = decryptMessages(hmac)
    unsignedHMACAscii = rsaKey.convertNumberToText(unsignedHMAC)
    generatedHMAC = sha256((requestMessage+"_"+clientID+"_"+publicKeyExponent+"_"+publicKeyModulus).encode()).hexdigest()
    print("Generated HMAC: "+str(generatedHMAC))
    print("Unsigned HMAC: "+str(unsignedHMACAscii))
    if unsignedHMACAscii == generatedHMAC:
        print("HMAC verification is done")
        print("Client Added succesfully")
        print()
        clientPublicKeyMap[clientID] = [publicKeyExponent,publicKeyModulus]
        return True
    return False

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

        
        # if clientDataList[0] == 'REQUEST':
        #     pass

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

