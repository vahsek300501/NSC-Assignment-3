import gmpy2
from gmpy2 import mpz
from copy import deepcopy
import math

class RSA:
    def generatePublicPrivateKeys(self,p,q):
        n = gmpy2.mul(p,q)
        phi_n = gmpy2.mul(gmpy2.sub(p,1),gmpy2.sub(q,1))
        fermatList = [mpz(65537),mpz(257),mpz(17),mpz(5),mpz(3)]
        e = None
        d = None

        for fermatNum in fermatList:
            z = deepcopy(phi_n)
            if z > fermatNum:
                tmpE = fermatNum
                tmpD = gmpy2.invert(tmpE,z)
                if gmpy2.gcd(tmpD,z) == mpz(1) and tmpE != tmpD:
                    e = tmpE
                    d = tmpD
                    break
        
        publicKey = (e,n)
        privateKey = (d,n)
        return publicKey, privateKey
    
    def generatePublicPrivateKeysUtil(self,p,q):
        n = gmpy2.mul(p,q)
        phi_n = gmpy2.mul(gmpy2.sub(p,1),gmpy2.sub(q,1))

        e = 2
        while(True):
            if math.gcd(e,phi_n) == 1:
                break
            e += 1
        
        publicKey = (e,n)

        d = 2
        while(True):
            if ((d*e)%phi_n)  == 1:
                break
            d += 1
        
        privateKey = (d,n)
        return publicKey, privateKey

    def convertTextToNumbers(self,text):
        finalText = ""
        for letter in text:
            asciiInteger = ord(letter)
            if len(str(asciiInteger)) < 3:
                finalText += '0'
                finalText += str(asciiInteger)
            else:
                finalText += str(asciiInteger)
        return int(finalText)

    def convertNumberToText(self,number):
        stringNum = str(number)
        if len(stringNum) % 3 != 0:
            stringNum = '0' + stringNum
        finalString = ""
        i = 0
        while(i < len(stringNum)):
            tmp = int(stringNum[i] + stringNum[i+1] + stringNum[i+2])
            finalString += chr(tmp)
            i += 3
        return finalString

    def encrypt(self,plainText,key):
        exponent = key[0]
        modulus = key[1]
        return gmpy2.powmod(plainText,exponent,modulus)

    def decrypt(self,cipherText,key):
        exponent = key[0]
        modulus = key[1]
        return gmpy2.powmod(cipherText,exponent,modulus)