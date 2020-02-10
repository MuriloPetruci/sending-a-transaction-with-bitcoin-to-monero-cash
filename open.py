#Os endereços P2SH são a codificação Base58 Check do hash160 de um script (conhecido como redimirScript). 
#Ele usa um byte de versão 0x05. 
#O restante da codificação é o mesmo, apenas a codificação Base58 Check.

def hash160(self, v):
        r = hashlib.new('ripemd160')
        r.update(hashlib.sha256(v).digest())
        return r


    def doublehash256(self, v):
        return hashlib.sha256(hashlib.sha256(v).digest())


    def ecdsaSECP256k1(self, digest):
        # SECP256k1 - Bitcoin curva elíptica
        sk = ecdsa.SigningKey.from_string(digest, curve=ecdsa.SECP256k1)                    
        return sk.get_verifying_key()

   def publicaddress1(self):

        prefix_a = b'\x04'
        prefix_b = b'\x00'

        digest = self.privkeyhex.digest()

        p = prefix_a + self.ecdsaSECP256k1(digest).to_string() # 1 + 32 bytes + 32 bytes
        self.pubkey = str(binascii.hexlify(p).decode('utf-8'))

        hash160 = self.hash160(p)

        m = prefix_b + hash160.digest()  
