import gmpy2
from gmpy2 import mpz
from copy import deepcopy

class RSA:
    def generatePublicPrivateKeys(self,p,q):
        n = gmpy2.mul(p,q)
        phi_n = gmpy2.mul(gmpy2.sub(p,1),gmpy2.sub(q,1))
        # print(n)
        # print(phi_n)
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


myRSA = RSA()
input = 59134142047097391415711665829499651268829714867873629452221437180020875546079785003551984470056813717093564420500159986154603823033729317680021797076022934379579431016711213509523797108343585966001109234595941953659764841100547545960215639798971131662338825336692505796269948855088804557694507455599363104977
publicKey, privateKey = myRSA.generatePublicPrivateKeys(11315021318077988822297698686245966994073231987629388711704681996437996088725429632461707272214616976409354431392925248076618696111389609344054891397490343,
                                                         6727003959482992676938581203928184232372129737758591272654595917870502706042256578008832342305931486750526418300360050790528820785214228675264283482234807)

decryptedNumber = myRSA.decrypt(input,privateKey)
print(myRSA.convertNumberToText(decryptedNumber))