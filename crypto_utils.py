import os
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

# Generates a public key and private key pair that can be used to encrypt and decrypt data
def generatePublicPrivateKeyPair(persist=False,filePath="key.pem",passphrase=b"mypassword"):
   
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    if persist:
        with open(filePath, "wb") as f:
            f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        ))

    return key,key.public_key()


# load the previously generated keypair from the disk
def loadKeyPairFromPath(filePath="key.pem",passphrase=b"mypassword"):

    if os.path.exists(filePath):
        with open(filePath, "rb") as key_file:
               privateKey = serialization.load_pem_private_key(
               key_file.read(),
               password=passphrase,
               backend=default_backend()
        )

        return (privateKey,privateKey.public_key())

    return False


def getCaPublicKey():
    (_,publicKey) = loadKeyPairFromPath()
    return publicKey


# sign the message
def signMessage(message,privateKey):
    signature = privateKey.sign(
            message,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
              salt_length = padding.PSS.MAX_LENGTH
            ),
           hashes.SHA256()
    )
    return signature

#Verifies that the payload and signature match each other using the publicKey
def verifySignature(signature,message):

    publicKey = getCaPublicKey()

    try:
        publicKey.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
               ),
                hashes.SHA256()
        )
        return True
    except:
        return False

def encryptMessage(message,publicKey):
    ciphertext = publicKey.encrypt(
            message,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
         )
       )
    return ciphertext


def decryptMessage(ciphertext, privateKey):
    return privateKey.decrypt(
            ciphertext,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
    )

def encodeData(data):
    return str(data).encode('utf-8')

def decodeBytes(bytes):
    return bytes.decode('utf-8')


def serializePublicKey(publicKey):
    return publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Returns a certificate  for the node given the proposed node ID and public key
def getNodeIdFromCA(nodeId,nodePublicKey):

    (caPrivateKey,_) = loadKeyPairFromPath()
            
    messageToSign = encodeData([nodeId,nodePublicKey])

    signature = caPrivateKey.sign(
        messageToSign,
        padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    certificate = [nodeId, nodePublicKey, signature]
    certificate = encodeData(certificate)

    return (certificate,nodePublicKey)

# Returns the NodeID present in the CA response passed to it
def extractNodeIdFromCAResponse(ciphertext, privateKey):
    plaintext = list(decryptMessage(ciphertext,privateKey))
    nodeId = plaintext[0]
    return nodeId