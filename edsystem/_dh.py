#!/usr/bin/python
# coding=utf-8

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto import Random
import random


def atoi(s):
    num = 0
    for v in s:
        offset = ord(v) - ord('0')
        num = num * 10 + offset
    return num


class Gen_Key():
    def __init__(self):
        random_generator = Random.new().read
        rsa = RSA.generate(2048, random_generator)
        self.private_pem = rsa.exportKey()
        with open('master-privatekey.pem', 'wb+') as f:
            f.write(self.private_pem)
        self.private_key = RSA.importKey(open('master-privatekey.pem').read())
        self.public_pem = rsa.publickey().exportKey()
        with open('master-publickey.pem', 'wb+') as f:
            f.write(self.public_pem)
        self.public_key = RSA.importKey(open('master-publickey.pem', 'r').read())

    def get_pri(self):
        return self.private_key

    def get_pub(self):
        return self.public_key

    def get_pub_pem(self):
        return self.public_pem


class ex_DH():
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def rsa_sign(self, message):
        # 对消息进行签名
        h = MD5.new(message.encode(encoding='utf-8'))
        signer = PKCS1_v1_5.new(self.private_key)
        signature = signer.sign(h)
        return signature

    def rsa_verify(self, message, signature):
        # 对消息进行签名验证
        h = MD5.new(message.encode(encoding='utf-8'))
        verifier = PKCS1_v1_5.new(self.public_key)
        if verifier.verify(h, signature):
            print("OK")
        else:
            print("Invalid Signature")

    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
    proot = 2

    def random_key(self):
        return (random.randint(2, self.p - 2))  # 得到私钥

    def fastExpMod(self, b, e, m):
        result = 1
        while e != 0:
            if (e & 1) == 1:
                # ei = 1, then mul
                result = (result * b) % m
            e >>= 1
            # b, b^2, b^4, b^8, ... , b^(2^n)
            b = (b * b) % m
        return result

    # A，B得到各自的计算数
    def get_calculation(self, X):
        return self.fastExpMod(self.proot, X, self.p)

    # A，B得到交换计算数后的密钥
    def get_key(self, X, Y):
        return self.fastExpMod(Y, X, self.p)


if __name__ == "__main__":
    test = Gen_Key()

    dh = ex_DH(test.get_pri(), test.get_pub())
    # signature=dh.rsa_sign('000')
    # dh.rsa_verify('000',signature)

    # 得到A的私钥
    XA = dh.random_key()
    print('A随机生成的私钥为：%d' % XA)

    # 得到B的私钥
    XB = dh.random_key()
    print('B随机生成的私钥为：%d' % XB)
    print('------------------------------------------------------------------------------')

    # 得待A的计算数
    YA = dh.get_calculation(XA)
    print('A的计算数为：%d' % YA)
    signature = dh.rsa_sign(str(YA))
    dh.rsa_verify(str(YA), signature)

    # 得到B的计算数
    YB = dh.get_calculation(XB)
    print('B的计算数为：%d' % YB)
    print('------------------------------------------------------------------------------')
    signature = dh.rsa_sign(str(YB))
    dh.rsa_verify(str(YB), signature)

    # 交换后A的密钥
    key_A = dh.get_key(XA, YB)
    print('A的生成密钥为：%d' % key_A)

    # 交换后B的密钥
    key_B = dh.get_key(XB, YA)
    print('B的生成密钥为：%d' % key_B)
    print('---------------------------True or False------------------------------------')

    print(key_A == key_B)
    print(str(1234))