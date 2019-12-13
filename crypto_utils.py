from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5 as pkcs
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from base64 import b64encode,b64decode
import hashlib
import time
import random
import binascii
def hash1(pwd):
    return(hashlib.sha256(str(pwd).encode('ascii')).hexdigest())

def hash2(msg):
    return hashlib.md5(msg.encode('ascii')).hexdigest()


"Key generation for RSA; arg=size of key"
def get_keys(num):
    private=RSA.generate(num)
    public=(private.publickey()).exportKey().decode("utf-8")
    private=private.exportKey().decode("utf-8")
    return public,private

"RSA enc"
def asym_encode(inp):
    (pubKey,msg)=inp
    keyPub=RSA.importKey(pubKey)
    cipher=PKCS1_v1_5.new(keyPub)
    cipher_text=cipher.encrypt(msg.encode())
    return(b64encode(cipher_text).decode('utf-8'))
"RSA dec"
def asym_decode(inp):
    (privKey,msg)=inp
    #print(inp)
    keyPriv=RSA.importKey(privKey)
    cipher=PKCS1_v1_5.new(keyPriv)
    decrypt_text=cipher.decrypt(b64decode(msg),None).decode()
    return decrypt_text


def len_msg(pub):
    public=pub
    i=0
    while True:
        msg='d'*(i+1)
        try:
            asym_encode((public,msg))
            i+=1
        except:
            return i
def messagebroker(msg,key):
    length=len_msg(key)
    res=[]
    l=len(msg)
    while True:
        mssg=msg[:length]
        msg=msg[length:]
        res.append(mssg)
        if l<=length:
            break
        l-=length
    return res

def enc(key,msgg):
    ret=[]
    for msg in msgg:
        ret.append(asym_encode((key,msg)))
    return ret

def encrypt(pub,priv,msg):
    ret=enc(pub,messagebroker(msg,pub))
    res=[]
    for i in ret:
        res.append(i)
        res.append(sign(i,priv))
    return res




def dec(priv,pub,lst):
    msg=''
    integrity=True
    for i in range(len(lst)//2):
        if integrity:
            msg+=asym_decode((priv,lst[2*i]))
            if verify_sign(lst[(2*i)],pub,lst[(2*i)+1]):
                integrity=True
            else:
                integrity=False
        if integrity:
            return msg
        else:
            return 'Message integrity compromised'

    return msg
def verify_sign(msg,pubKey,sig):
    digest = SHA256.new()
    digest.update(msg.encode())
    pubKey=RSA.importKey(pubKey)
    verifier = pkcs.new(pubKey)
    verified = verifier.verify(digest,b64decode(sig.encode('utf-8')))
    return verified
def sign(msg,privKey):
    digest = SHA256.new()
    digest.update(msg.encode())
    private_key=RSA.importKey(privKey)
    signer = pkcs.new(private_key)
    sig = signer.sign(digest)
    return (b64encode(sig).decode('utf-8'))
"AES enc"
def enc_sym(key,msg):
    k=(binascii.hexlify((key)[:8].encode('ascii')))
    m=AES.new(k,AES.MODE_EAX,(str(hash(key))).encode()).encrypt(msg.encode('ascii'))
    return b64encode(m).decode()

"AES dec"
def dec_sym(key,msg):
     return ((AES.new(binascii.hexlify((key)[:8].encode('ascii')),AES.MODE_EAX,(str(hash(key))).encode())).decrypt(b64decode(msg.encode()))).decode()
