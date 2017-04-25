import PyKCS11
import sys
from M2Crypto import X509
import OpenSSL
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA, SHA256
import urllib, shutil
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
import os
from security import AESCipher

class CCUtils():
    CERT_LABEL = 'CITIZEN AUTHENTICATION CERTIFICATE'
    SUBCA_LABEL = 'AUTHENTICATION SUB CA'
    KEY_LABEL = 'CITIZEN AUTHENTICATION KEY'
    def get_cert(self, certLabel,slot=0):
        lib = '/usr/local/lib/libpteidpkcs11.so'
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        try:
            slots = pkcs11.getSlotList()
            s = slots[slot]
        except:
            print 'Slot list failed: ', str(sys.exc_info()[1])
            return ('Failed to find a smart card reader!', None)
        try:
            session = pkcs11.openSession(s)
        except:
            print 'Session opening failed', str(sys.exc_info()[1])
            return ('Failed to open citizen card!', None)
        objs = session.findObjects(template=(
                (PyKCS11.LowLevel.CKA_LABEL, certLabel),
                (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_CERTIFICATE)))
        if len(objs) == 0:
            return 'CC falhou'
        try:
            der = ''.join(chr(c) for c in objs[0].to_dict()['CKA_VALUE'])
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der)
            # we need to return as pem
            pem_data = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509)
        except:
            return 'invalid'
        return pem_data

    def refresh_DeltaCrl(self, obj):
        ext = obj.get_extension(index=6).get_data()
        name = ext.split('/')[-1]
        try:
            fileHandle = urllib.URLopener()
            fileHandle.retrieve(ext[ext.index('http'):], os.getcwd() + '/CRLS/' + name)
        except Exception:
            pass

    def get_cckey(self, cert):
        obj_509 = X509.load_cert_string(cert,format=1)
        pubKey = RSA.importKey(obj_509.get_pubkey().as_der())
        return pubKey.exportKey(format='PEM')


    def get_data_cert(self, cert):
        subject_ = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert)
        subject = subject_.get_subject().get_components()
        for sub in subject:
            if sub[0]=='CN':
                name = sub[1]
            elif sub[0]=='serialNumber':
                sn = sub[1][2:]
        return name,sn

    def sign_sv(self, data):
        with open(os.path.join(os.getcwd(), 'SV_Certs', 'aesPrivKeySV'), 'r') as myfile:
            raw = myfile.read()
        pem = AESCipher.decrypt(str("ba9215de7a12407aa225762330bf3919"), raw )
        private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pem, '')
        return OpenSSL.crypto.sign(private_key,data,b"sha256")

    def verify_svsignature(self, cert, sig, data):
        try:
            obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert)
            ret = OpenSSL.crypto.verify(obj, sig, data, b"sha256")
            if ret is None: #it returns None if true ... WHYYY
                return True
            else:
                return False
        except:
            return False

    def sign(self, data, session=None, slot=0):
        if isinstance(session, PyKCS11.Session):
            key = session.findObjects(template=((PyKCS11.LowLevel.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY'),
                                                (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PRIVATE_KEY),
                                                (PyKCS11.LowLevel.CKA_KEY_TYPE, PyKCS11.LowLevel.CKK_RSA)))[0]
            mech = PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_SHA1_RSA_PKCS, '')
            sig = session.sign(key, data, mech)
            ret = ''.join(chr(c) for c in sig)
            return ret, session
        else:
            lib = '/usr/local/lib/libpteidpkcs11.so'
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(lib)
            slots = pkcs11.getSlotList()
            session = pkcs11.openSession(slots[slot])
            key = session.findObjects(template=((PyKCS11.LowLevel.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY'),
                                                (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PRIVATE_KEY),
                                                (PyKCS11.LowLevel.CKA_KEY_TYPE, PyKCS11.LowLevel.CKK_RSA)))[0]
            mech = PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_SHA1_RSA_PKCS, '')
            sig = session.sign(key, data, mech)
            ret = ''.join(chr(c) for c in sig)
            return ret, session # we need to keep session. it always keeps even if we dont return it. dont know why

    def validate_svcert(self, cert):
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert)    #card
        chain = []
        f = open(os.path.join(os.getcwd(), 'SV_Certs', 'CA.pem'), 'r')
        obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
        f.close()
        chain_error = None
        try:
            store = OpenSSL.crypto.X509Store()
            store.add_cert(obj)
            store_ctx = OpenSSL.crypto.X509StoreContext(store, cert_obj)
            if store_ctx.verify_certificate() is None:
                return True
        except Exception, e:
            if isinstance(e, OpenSSL.crypto.X509StoreContextError):
                chain_error = e.certificate
            return False
        return False

    def getEnts(self, cert):
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        subca_subject = [x[1] for x in cert_obj.get_issuer().get_components() if x[0]=='CN']
        with open(os.path.join(os.getcwd(), 'CC_Certs', 'EC_de_Autenticacao_do_Cartao_de_Cidadao_' + str(subca_subject[0][-4:]) + '.pem'), 'r') as myfile:
            subca_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, myfile.read())
        subca_issuer = [x[1] for x in subca_obj.get_issuer().get_components() if x[0]=='CN']
        return subca_subject[0][-4:], subca_issuer[0][-3:]

    def validate_cert(self, cert):
        if os.path.isdir(os.getcwd()+'/CRLS'):
            try:
                shutil.rmtree(os.getcwd() + '/CRLS/')
                os.makedirs(os.getcwd() + '/CRLS/')
            except Exception:
                pass
        else:
            try:
                os.makedirs(os.getcwd() + '/CRLS/')
            except Exception:
                pass
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert)
        tup = self.getEnts(cert)
        chain = []
        chain_crl = []
        subca_filename = 'EC_de_Autenticacao_do_Cartao_de_Cidadao_' + str(tup[0]) + '.pem'
        cc_filename = 'Cartao_de_Cidadao_' + str(tup[1]) + '.pem'
        trusted_certificates = [subca_filename, cc_filename, 'ECRaizEstado.pem', 'Baltimore_CyberTrust_Root.pem']
        crl_s = []
        crl_s.append(self.getCrl(cert_obj, 5))
        for tc_filename in trusted_certificates:
            f = open(os.path.join(os.getcwd(), 'CC_Certs', tc_filename), 'r')
            obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
            if 'EC' in tc_filename and 'Root' not in tc_filename:
                crl_s.append(self.getCrl(obj, 5))
            elif 'Cartao' in tc_filename:
                crl_s.append(self.getCrl(obj, 6))
            if not obj.has_expired():
                chain.append(obj)
            else:
                return False
            f.close()
        self.refresh_DeltaCrl(cert_obj)
        for filename in os.listdir(os.getcwd()+'/CRLS/'):
            f = open(os.getcwd() + '/CRLS/' + filename, 'r')
            chain_crl.append(OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, f.read()))
            f.close()
        chain_error = None
        try:
            store = OpenSSL.crypto.X509Store()
            for cert in chain:
                store.add_cert(cert)
            for crl in chain_crl:
                store.add_crl(crl)
            store.set_flags(flags=OpenSSL.crypto.X509StoreFlags.CRL_CHECK_ALL)
            store_ctx = OpenSSL.crypto.X509StoreContext(store, cert_obj)
            if store_ctx.verify_certificate() is None:
                return True
        except Exception, e:
            if isinstance(e, OpenSSL.crypto.X509StoreContextError):
                chain_error = e.certificate
            return False
        return False

    def verifySignature(self, pem, data, signature):
        keypub = RSA.importKey(self.get_cckey(pem))
        verifier = PKCS1_v1_5.new(keypub)
        digest = SHA.new(data=data)
        return verifier.verify(digest, signature)

    def getCrl(self,obj, idx):
        wget = obj.get_extension(index=idx).get_data()
        name = wget.split('/')[-1]
        try:
            fileHandle = urllib.URLopener()
            fileHandle.retrieve(wget[wget.index('http'):], os.getcwd() + '/CRLS/' + name)
        except Exception:
            pass
        return name

    def getSvCert(self):
        with open(os.path.join(os.getcwd(), 'SV_Certs', 'aesSV'), 'r') as myfile:
            raw = myfile.read()
        pem = AESCipher.decrypt(str("1e500f6e8fba4b3d1b88971d1115111d"), raw )
        return pem
