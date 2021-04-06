import asyncio, time, struct
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac # avoid name collision
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from scapy.all import *
from scapy.layers.tls.keyexchange import _TLSSignature
from scapy.layers.tls.handshake import _TLSCKExchKeysField
from datetime import datetime, timedelta

from .debug import Debug
from .utils import DHParamsSerialization

randstring = Debug.replayable(Debug.random)
timestamp  = Debug.replayable(time.time)
ServerDHParams = Debug.replayable(ServerDHParams, DHParamsSerialization)

class TLSSession:
    def __init__(self):
        # manually set value
        self.tls_version = 0x303
        self.read_seq_num = 0
        self.write_seq_num = 0
        self.PRF = PRF()

        self.client_time = None
        self.client_random_bytes = None
        
        self.server_time = None
        self.server_random_bytes = None

        self.server_rsa_privkey = None
        self.client_dh_params = None

        self.mac_key_size = 20
        self.enc_key_size = 16
        #self.iv_size = 16

        self.handshake = True

        # automatically calculated
        self.client_random = None
        self.server_random = None
        self.server_dh_params = ServerDHParams()
        #self.server_dh_params.fill_missing()
        self.server_dh_privkey = self.server_dh_params.tls_session.server_kx_privkey
        self.client_dh_pubkey = None
        self.pre_master_secret = None
        self.master_secret = None
        self.read_mac = None
        self.write_mac = None
        self.read_enc = None
        self.write_enc = None
        self.read_iv = None
        self.write_iv = None
        self.key_block_len = (2*self.mac_key_size)+(2*self.enc_key_size)#+(2*self.iv_size)

        self.handshake_messages = b""

    def set_client_random(self, time_part, random_part):
        # Y STUDENT TODO
        """
        1. set client_time, client_bytes
        2. calculate client_random. There is a method for this
        """
        self.client_time = int(time_part)
        self.client_random_bytes = random_part
        self.client_random = self.time_and_random(time_part,random_part)
        pass

    def set_server_random(self):
        # Y STUDENT TODO
        """
        1. set server_time, server_bytes
        2. calculate server_random. There is a method for this
        """
        self.server_time = int(timestamp())
        self. server_random_bytes = randstring(28)
        self.server_random = self.time_and_random(self.server_time, self.server_random_bytes)
        pass

    def set_server_rsa_privkey(self, rsa_privkey):
        self.server_rsa_privkey = rsa_privkey

    def set_client_dh_params(self, client_params):
        self.client_dh_params = client_params  
        p = pkcs_os2ip(self.server_dh_params.dh_p)
        g = pkcs_os2ip(self.server_dh_params.dh_g)
        pn = dh.DHParameterNumbers(p,g)
        y = pkcs_os2ip(self.client_dh_params.dh_Yc)
        public_key_numbers = dh.DHPublicNumbers(y, pn)
        self.client_dh_pubkey = public_key_numbers.public_key(default_backend())
        self._derive_keys()

    def _derive_keys(self):
        # Y STUDENT TODO
        """
        1. calculate pre_master_secret
        2. calculate master_secret
        3. calculate a key block
        4. split the key block into read and write keys for enc and mac
        """
        if self.pre_master_secret is None:
            self.pre_master_secret = self.server_dh_privkey.exchange(self.client_dh_pubkey)
        self.master_secret = self.PRF.compute_master_secret(
            pre_master_secret = self.pre_master_secret,
            client_random = self.client_random,
            server_random = self.server_random)
        Debug.print("Master secret:", self.master_secret.hex().upper())
        key_block = self.PRF.derive_key_block(
            master_secret = self.master_secret,
            client_random = self.client_random,
            req_len = self.key_block_len)
        
        self.read_mac, key_block  = key_block[:self.mac_key_size], key_block[self.mac_key_size:]
        self.write_mac, key_block = key_block[:self.mac_key_size], key_block[self.mac_key_size:]
        self.read_enc, key_block  = key_block[:self.enc_key_size], key_block[self.enc_key_size:]
        self.write_enc, key_block = key_block[:self.enc_key_size], key_block[self.enc_key_size:]
        #self.read_iv, key_block   = key_block[:self.iv_size],      key_block[self.iv_size:]
        #self.read_iv, key_block   = key_block[:self.iv_size],      key_block[self.iv_size:]

    def tls_sign(self, bytes):
        """
        1. Create a TLSSignature object. set sig_alg to 0x0401
        2. use this object to sign the bytes
        """
        sig = None # this should be the signature object

        sig = _TLSSignature(sig_alg=0x0401)
        sig._update_sig(bytes, self.server_rsa_privkey)
        
        return sig

    def hmac_pkt (self, hdr, msg, mode, **kargs):
        if mode == "receive":
            seq_num = struct.pack("!Q", self.read_seq_num)
            self.read_seq_num += 1
            key = self.read_mac
        elif mode == "send":
            seq_num = struct.pack("!Q", self.write_seq_num)
            self.write_seq_num += 1
            key = self.write_mac
        elif mode == "test":
            Debug.print("Test hmac on seq {} hdr {}, msg {}, msglen {}".format(kargs["seq_num"], hdr.hex(), msg.hex(), len(msg)))
            seq_num = struct.pack("!Q", kargs["seq_num"])
            key = self.write_mac
        else:
            raise Exception("UNkown hmac code {}".format(mode))
        
        tls_hmac = crypto_hmac.HMAC(key, hashes.SHA1(), default_backend())
        tls_hmac.update(seq_num + hdr + msg)
        return tls_hmac.finalize()
    

    def decrypt_tls_pkt(self, tls_pkt, **kargs):
        print("\n\n\n\n\n\n\n*******************")
        # scapy screws up and changes the first byte if it can't decrypt it
        # from 22 to 23 (handshake to application). Check if this happens and fix
        packet_type = tls_pkt.type
        tls_pkt_bytes = raw(tls_pkt)
        tls_pkt_bytes = struct.pack("!B",packet_type)+tls_pkt_bytes[1:]
        
        print("**** here 1")

        # Y STUDENT TODO
        """
        1. The beginning of this function, already provided, extracts the data from scapy
        2. Do the TLS decryption process on tls_pkt_bytes
        3. Technically, you don't have to do the hmac. wget will do it right
        4. But if you check the hmac, you'll know your implementation is correct!
        5. return ONLY the decrypted plaintext data
        6. NOTE: When you do the HMAC, don't forget to re-create the header with the plaintext len!
        """
        plaintext = b''
        
        hdr, efrag = tls_pkt_bytes[:5], tls_pkt_bytes[5:]
        pkt_type = struct.unpack("!B", hdr[:1])
        Debug.print('Decrypt Packet Type', pkt_type, hdr.hex())
        Debug.print("Decrypt got header of size {}, fragment of size {}".format(len(hdr), len(efrag)))
        explicit_iv, encrypted_data = efrag[:16], efrag[16:]
        print("explicit_iv")
        print(explicit_iv)
        print("read_enc")
        print(read_enc)
        Debug.print("Decrypt with key of size {} and iv of size {}".format(len(self.read_enc), len(explicit_iv)))
        cipher = Cipher(algorithms.AES(self.read_enc), modes.CBC(explicit_iv), default_backend()).decryptor()        
        Debug.print("Attempt to decrypt {} bytes".format(len(encrypted_data)))
        plaintext_data = cipher.update(encrypted_data) + cipher.finalize()
        Dbug.print("paintext size: ", len(plaintext_data))
        pad_len = int(plaintext_data[-1]) + 1
        Debug.print("Pad: {}, len: {}".format(plaintext_data[-pad_len:].hex(), pad_len))
        plaintext_wo_pad = plaintext_data[:-pad_len]
        mac = plaintext_wo_pad[-20:]
        plaintext_only = plaintext_wo_pad[:-20]
        Debug.print("Decrypt plaintext size: {}, mac_size {}".format(len(plaintext_only), len(mac)))
        mac_hdr = hdr[:3] + struct.pack("!H", len(plaintext_only))
        Debug.print("Decrypt plaintext header", mac_hdr.hex())

        """print("Process? packet type is {}".format(struct.unpack("!B", mac_hdr[:1])))
        m = TLS(mac_hdr+plaintext_only)
        m.show2()"""

        if not kargs.get("test", False):
            signature = self.hmac_pkt(mac_hdr, plaintext_only, "receive")
        else:
            signature = self.hmac_pkt(mac_hdr, plaintext_only, "test", **kargs)
            Debug.print("Test signature. Len {}. Hex={}".format(len(signature), signature.hex()))
        if signature != mac:
            Debug.print(signature.hex())
            DEbug.print(mac.hex())
            raise Exception("Invalid MAC on packet")
        plaintext = plaintext_only

        return plaintext

    def encrypt_tls_pkt(self, tls_pkt, test_iv=None):
        pkt_type = tls_pkt.type
        tls_pkt_bytes = raw(tls_pkt)

        # scapy can make some mistakes changing the first bytes on handshakes
        if tls_pkt_bytes[0] != pkt_type:
            Debug.print(tls_pkt_bytes[0], pkt_type)
            tls_pkt_bytes = struct.pack("!B",pkt_type)+tls_pkt_bytes[1:]
        
        # no matter what, should only have one msg
        plaintext_msg = tls_pkt.msg[0]
        plaintext_bytes = raw(plaintext_msg)
        
        # Y STUDENT TODO
        """
        1. the beginning of this function, already provided, extracts the data from scapy
        2. Do the TLS encryption process on the plaintext_bytes
        3. You have to do hmac. This is the write mac key
        4. You have to compute a pad
        5. You can use os.urandom(16) to create an explicit IV
        6. return the iv + encrypted data
        """
        
        ciphertext = b""
        
        Debug.print_packet(plaintext_msg)
        Debug.print("In encrypt. Plaintext of tls pkt msg is ", len(plaintext_bytes))

        orig_header = tls_pkt_bytes[:5]
        mac = self.tls_sign(orig_header, plaintext_bytes, "send")
        pad_len = 16-((len(plaintext_bytes)+len(mac))%16)
        Debug.print("encrypt pad len", pad_len)
        pad = struct.pack('!B', pad_len-1)*pad_len
        all_plaintext = plaintext_bytes + mac + pad
        
        if test_iv is None:
            explicit_iv = os.urandom(16)
        else:
            explicit_iv = test_iv
        
        cipher = Cipher(algorithms.AES(self.write_enc), modes.CBC(explicit_iv), default_backend()).encryptor()
        ciphertext = cipher.update(all_plaintext) + cipher.finalize()
        efrag = explicit_iv + ciphertext
        encrypted_bytes = tls_pkt_bytes[:3]+struct.pack("!H",len(efrag))+efrag
        ciphertext = encrypted_bytes

        return ciphertext

    def record_handshake_message(self, m):
        self.handshake_messages += m

    def compute_handshake_verify(self, mode):
        # Y STUDENT TODO
        """
        1. use PRF.compute_verify_data to compute the handshake verify data
            arg_1: the string "server"
            arg_2: mode
            arg_3: all the handshake messages so far
            arg_4: the master secret
        """
        verify_data = b""
        
        verify_data = self.PRF.compute_verify_data("server", mode, self.handshake_messages, self.master_secret)

        return verify_data

    def time_and_random(self, time_part, random_part=None):
        if random_part is None:
            random_part = randstring(28)
        return struct.pack("!I",time_part) + random_part

        
        
