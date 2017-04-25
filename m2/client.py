# encoding: utf-8
#
# Alvaro.martins@ua.pt
# DETI UA 2016
# vim setings:
# :set expandtab ts=4
import copy
import socket
import netifaces
from select import select
import sys
import argparse
from termcolor import colored
from DiffieHellmanUtils import DHUtils
import datetime
#
import traceback
import time
from security import *
from CCUtils import CCUtils
from uuid import getnode as get_mac
#
UNKNOWN = None

BUFSIZE = 512 * 1024
MAX_BUFSIZE = 64 * 1024

# sv states
CONNECTED = 1
WAITING_CONNECTION = 2
NOT_CONNECTED = 3
REFRESHING = 4

# req states -> list, connect, client-connect
IDLE = 1
WAITING = 2
ACKED = 3

# comm states -> client-com
SENT = 1
# WAITING = 2 # overlaps with req state
SV_VALIDATED = 3
ARRIVED = 4


MAX_MSG_COUNT = 10
MAX_SV_MESSAGE = 30

CHALLENGE_SIZE = 10

CC = CCUtils()


class ServerConnection:
    state = NOT_CONNECTED
    cipher = UNKNOWN
    diffie_utils = DHUtils()
    refresh_buffer = []
    phase = 1
    message_counter = 1
    last_received = 0
    count = 0
    sv_rsa_pub = UNKNOWN
    my_rsa_key = RSA.generate(2048)
    my_rsa_priv = my_rsa_key.exportKey()
    my_rsa_pub = my_rsa_key.publickey().exportKey()
    cert = UNKNOWN
    clg = "".join([str(random.randint(0, 9)) for i in range(CHALLENGE_SIZE)])
    session = None


class Friend:
    com_counter = 1
    message_counter = 1
    message_buffer = []
    last_received = 0
    message_history = dict()
    message_last = -1
    name = ""
    cid = UNKNOWN
    cipher = UNKNOWN
    state = NOT_CONNECTED
    phase = 1
    msg_count = 0
    level = UNKNOWN
    cert = UNKNOWN
    clg = "".join([str(random.randint(0, 9)) for i in range(CHALLENGE_SIZE)])
    friend_rsa_pub = UNKNOWN
    diffie_utils = DHUtils()
    my_rsa_key = RSA.generate(2048)
    my_rsa_priv = my_rsa_key.exportKey()
    my_rsa_pub = my_rsa_key.publickey().exportKey()
    session = None


class Client:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))
    ccnt = {}
    bufin = ""
    debug = False
    lstsilence = 0
    name = ""
    cid = UNKNOWN
    lststate = IDLE
    lstbuffer = UNKNOWN
    server_con = ServerConnection()
    tmp = UNKNOWN
    lst_clients = {}
    def __init__(self, slot):
        self.supportedciphers = ['DHE_RSA_AES256_SHA512',
                                 'DHE_RSA_AES256_SHA256',
                                 'DHE_RSA_AES128_SHA512',
                                 'DHE_RSA_AES128_SHA256']
        self.slot = slot
        self.cert = CC.get_cert( CC.CERT_LABEL, slot)
        namecc, numbercc = CC.get_data_cert(self.cert)
        self.name = namecc
        self.cid = numbercc

    def send(self, obj):
        if self.server_con.state == REFRESHING:
            self.server_con.refresh_buffer += [obj]
            return
        if obj['type'] == 'secure':
            cl_ack = False
            if obj['payload']['type'] == 'ack':
                if obj['payload']["topic"] == "client-connect":
                    cl_ack = True
            if 'dst' in obj['payload'] and obj['payload']['type'] != 'client-connect' and not cl_ack:
                obj['payload']['data']['ID'] = self.lst_clients[obj['payload']['dst']].message_counter
                self.lst_clients[obj['payload']['dst']].message_counter += 1
                obj = self.format_client(self.lst_clients[obj['payload']['dst']], obj)
                cipher = self.lst_clients[obj['payload']['dst']].cipher
                dh = self.lst_clients[obj['payload']['dst']].diffie_utils.shared_key
                HMAC = Utils.attach_HMAC(obj['payload'],cipher,dh)
                SIGNED, self.lst_clients[obj['payload']['dst']].session = CC.sign(json.dumps(obj['payload'], sort_keys=True), self.lst_clients[obj['payload']['dst']].session,self.slot )
                obj["payload"] = HMAC
                obj["payload"]["signed"] = base64.b64encode(SIGNED)
            elif obj["payload"]["type"] == "client-connect" or cl_ack:
                if obj["payload"]["phase"] >= 3:
                    dst = self.lst_clients[obj['payload']['dst']]
                    SIGNED, dst.session = CC.sign(json.dumps(obj["payload"], sort_keys=True), dst.session,self.slot)
                    if obj["payload"]["phase"] >=5:
                        cipher = dst.cipher
                        dh = dst.diffie_utils.shared_key
                        HMAC = Utils.attach_HMAC(obj["payload"],cipher,dh)
                    else:
                        HMAC = obj["payload"]
                    obj["payload"] = HMAC
                    obj["payload"]["signed"] = base64.b64encode(SIGNED)
            obj['payload']['ID'] = self.server_con.message_counter
            self.server_con.message_counter+=1
            obj = self.format_secure(obj)
            cipher = self.server_con.cipher
            dh = self.server_con.diffie_utils.shared_key
            HMAC = Utils.attach_HMAC(obj,cipher,dh)
            SIGNED, self.server_con.session = CC.sign(json.dumps(obj, sort_keys=True), self.server_con.session, self.slot)
            obj = HMAC
            obj["signed"] = base64.b64encode(SIGNED)

        elif obj["type"] == "connect":
            obj['ID'] = self.server_con.message_counter
            self.server_con.message_counter+=1
            if obj["phase"] >= 3:
                SIGNED, self.server_con.session = CC.sign(json.dumps(obj, sort_keys=True), self.server_con.session, self.slot)
                if obj["phase"] >=5:
                    cipher = self.server_con.cipher
                    dh = self.server_con.diffie_utils.shared_key
                    HMAC = Utils.attach_HMAC(obj,cipher,dh)
                else:
                    HMAC = obj
                obj = HMAC
                obj["signed"] = base64.b64encode(SIGNED)


        try:
            self.client_socket.send(json.dumps(obj) + "\n\n")
            if self.server_con.count > MAX_SV_MESSAGE and not self.debug:
                self.server_con.count = 0
                self.refresh_sv()

        except Exception as e :
            print e
            print traceback.print_exc()
            print colored("error sending", "red")

    def sendmessage(self):
        idx = 0
        idtoidx = {}
        for c in self.lst_clients.keys():
            if self.lst_clients[c].state == CONNECTED:
                idtoidx[idx] = self.lst_clients[c].cid
                print str(idx) + " -> " + str(self.lst_clients[c].cid) + ": " + self.lst_clients[c].name
                idx += 1
        if idx == 0:
            return
        dst_idx = 0
        while True:
            try:
                dst_idx = raw_input(colored("dst idx('-1' to quit): ", "magenta"))
                dst_idx = int(dst_idx)
                if dst_idx == -1:
                    return
                if not (dst_idx < 0 or dst_idx >= idx):
                    break
            except:
                print colored("plis pick a valid index", "yellow")

        dst = self.lst_clients[idtoidx[dst_idx]]
        msg = raw_input("msg:")
        data = {
            "type": "secure",
            "payload": {
                "type": "client-com",
                "src": self.cid,
                "dst": dst.cid,
                "data": {
                    "msg": msg,
                    "com_ID": dst.com_counter
                }
            }
        }
        print colored("sent message nr: "+ str(dst.com_counter)+ " to " + dst.name + ": ", "cyan") + colored(msg, "white")
        self.send(data)
        self.lst_clients[dst.cid].com_counter += 1
        self.lst_clients[dst.cid].msg_count += 1

    def refresh(self, dst):
        self.client_disconnect(dst)
        self.connect_client(dst)

    def refresh_sv(self):
        self.tmp = ServerConnection()
        self.tmp.state = CONNECTED
        self.tmp.cipher = self.server_con.cipher
        # no futuro se suportarmos mais cifras que nao utilizem RSA e DHE
        # temos de alterar aqui
        data = {
            "type": "secure",
            "payload": {
                "type": "refresh",
                "data": {
                    "df_pr_root": self.tmp.diffie_utils.pr_root,
                    "modulus_prime": self.tmp.diffie_utils.prime,
                    "pub": self.tmp.diffie_utils.my_pub,
                    "rsa_pub": self.tmp.my_rsa_pub
                }
            }
        }
        self.send(data)
        self.server_con.state = REFRESHING

    def connect_client(self, dst=None):
        if dst is None:
            idx = 0
            idtoidx = {}
            for c in self.lst_clients:
                idtoidx[idx] = self.lst_clients[c].cid
                print str(idx) + " -> " + str(self.lst_clients[c].cid) + ": " + self.lst_clients[c].name
                idx += 1
            dst_idx = 0
            if idx == 0:
                print colored("There are no listed clients", "red")
                return
            while True:
                try:
                    dst_idx = raw_input(colored("dst idx('-1' to quit): ", "magenta"))
                    dst_idx = int(dst_idx)
                    if dst_idx == -1:
                        return
                    if not (dst_idx < 0 or dst_idx >= idx):
                        break
                except:
                    print colored("plis pick a valid index", "yellow")
            dst = self.lst_clients[idtoidx[dst_idx]]
        data = {
            "type": "secure",
            "payload": {
                "type": "client-connect",
                "src": self.cid,
                "dst": dst.cid,
                "name": self.name,
                "phase": 1,
                "ciphers": self.supportedciphers,
                "data": {
                        "cert": base64.b64encode(self.cert),
                        "machine_id": machine_fingerprint()
                }
            }
        }
        self.send(data)
        self.lst_clients[dst.cid].state = WAITING_CONNECTION
        print colored("trying to connect to: ", "green") + colored(dst.cid, "blue")
        print colored("this may take a while, please be patient", "green")

    def client_disconnect(self, dst=None):
        if dst is None:
            idx = 0
            idtoidx = {}
            for c in self.lst_clients:
                if self.lst_clients[c].state == CONNECTED:
                    idtoidx[idx] = self.lst_clients[c].cid
                    print str(idx) + " -> " + str(self.lst_clients[c].cid) + ": " + self.lst_clients[c].name
                    idx += 1
            if idx == 0:
                print colored("you are not connected to any client", "yellow")
                return
            dst_idx = 0
            while True:
                try:
                    dst_idx = raw_input(colored("dst idx('-1' to quit): ", "magenta"))
                    dst_idx = int(dst_idx)
                    if dst_idx == -1:
                        return
                    if not (dst_idx < 0 or dst_idx >= idx):
                        break
                except:
                    print colored("plis pick a valid index", "yellow")
            dst = self.lst_clients[idtoidx[dst_idx]]
        if dst.state == CONNECTED:
            msg = {"type": "secure",
                   "payload": {"type": "client-disconnect",
                               "src": self.cid,
                               "dst": dst.cid,
                               "data": {

                                    }
                               }
                   }
            print colored(self.lst_clients[dst.cid].name, "cyan") + colored(" disconnected", "red")
            self.send(msg)
            del self.lst_clients[dst.cid]
            self.lst_clients[dst.cid] = Friend()
            self.lst_clients[dst.cid].cid = dst.cid
            self.lst_clients[dst.cid].name = dst.name

    def connect(self):
        data = {"type": "connect", "phase": self.server_con.phase,
                "name": self.name,
                "id": self.cid,
                "ciphers": self.supportedciphers,
                "data":{
                    "cert": base64.b64encode(self.cert)
                }
                }
        self.send(data)
        self.server_con.state = WAITING_CONNECTION

    def lst(self):
        if (not self.server_con.state == CONNECTED) and (not self.server_con.state == REFRESHING):
            print colored("You must be "
                          "connected to the server to "
                          "list all clients!", "red")
            return
        if self.lststate == WAITING or self.lststate == ACKED:
            print colored("A list request has already been made, please be patient", "yellow")
            return
        data = {
            "type": "secure",
            "payload": {"type": "list",
                        "data": "nhanha"
                        }
        }
        self.send(data)
        self.lststate = WAITING

    def parsereqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""
        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            print colored("overflow at parseReqs", "red")
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split("\n\n")
        self.bufin = reqs[-1]
        if len(self.bufin) > 1:
            print colored("BUFIN: " + self.bufin, "green")
        return reqs[:-1]

    def handleconnect(self, request):
        if self.server_con.state == CONNECTED:
            print colored("Server is already connected", "red")
            return

        if not all(k in request.keys() for k in ("ciphers", "phase", "data")):
            print colored("Connect message with missing fields", "red")
            return

        if self.server_con.state != WAITING_CONNECTION:
            print colored("why are we getting connects without expecting them?", "yellow")
            return

        # something is happening, we cut connection and try later
        if request["phase"] < self.server_con.phase:
            print colored("phase smaller than should be", "red")
            self.server_con.phase = 1
            self.server_con.state = NOT_CONNECTED
            return

        self.server_con.phase = request['phase'] + 1

        msg = {'type': 'connect', 'phase': self.server_con.phase, 'ciphers': request["ciphers"],
               "name": self.name,
               "id": self.cid,
               "data": {
                   "df_pr_root": "",
                   "modulus_prime": "",
                   "pub": "",
                   "hmac": "",
                   "salt": "",
                   "rsa_pub": ""
               }
               }
        if self.debug and request['ciphers'][0] == "NONE":
            print colored("Connected to server", "green")
            self.server_con.state = CONNECTED
            self.server_con.cipher = request['ciphers'][0]
            return
        (key_agr, asym, sym, hashm) = request['ciphers'][0].split("_")
        if key_agr in ['DHE'] and asym in ['RSA'] and sym in ["AES128", "AES256"] and hashm in ['SHA256', 'SHA512']:
            mode = SHA256
            if hashm == "SHA512":
                mode = SHA512
            if request['phase'] == 2:
                self.server_con.cipher = request['ciphers'][0]
                msg['data']['df_pr_root'] = self.server_con.diffie_utils.pr_root
                msg['data']['modulus_prime'] = self.server_con.diffie_utils.prime
                msg['data']['pub'] = self.server_con.diffie_utils.my_pub
                signed , self.server_con.session = CC.sign(request['data']['clg'], self.server_con.session, self.slot)
                msg['data']['signed'] = base64.b64encode(signed)
                msg['data']['clg'] = self.server_con.clg
                self.server_con.cert = base64.b64decode(request['data']['cert'])
                valid = CC.validate_svcert(self.server_con.cert)
                if not valid:
                    print colored("Server sent invalid cert", "red")
                    self.stop()
                self.send(msg)
                return
            elif request['phase'] == 4:
                if self.server_con.diffie_utils.pr_root == request["data"]["df_pr_root"] and \
                                self.server_con.diffie_utils.prime == request["data"]["modulus_prime"]:
                    self.server_con.diffie_utils.other_pub = request["data"]["pub"]
                    self.server_con.diffie_utils.shared_key = pow(self.server_con.diffie_utils.other_pub,
                                                    self.server_con.diffie_utils.private,
                                                    self.server_con.diffie_utils.prime)
                    salt = random.getrandbits(64)
                    hashed = pyscrypt.hash(password=str(self.server_con.diffie_utils.shared_key),
                                           salt=str(salt),
                                           N=1024,
                                           r=1,
                                           p=1,
                                           dkLen=32)
                    success = CC.verify_svsignature(self.server_con.cert,
                                                        base64.b64decode(request['data']['signed']),
                                                        self.server_con.clg)
                    if not success:
                        print colored("we are not talking to the server!!!","red")
                        self.stop()
                    self.server_con.clg = "".join([str(random.randint(0, 9)) for i in range(CHALLENGE_SIZE)])
                    msg['data']["rsa_pub"] = self.server_con.my_rsa_pub
                    msg['data']['hmac'] = HMAC.new(key=str(hashed.encode('hex')),
                                                   msg=self.server_con.my_rsa_pub,
                                                   digestmod=mode).hexdigest()
                    msg['data']['salt'] = salt
                    self.send(msg)

                return
            elif request['phase'] == 6:
                salt = request['data']['salt']
                hashed = pyscrypt.hash(password=str(self.server_con.diffie_utils.shared_key),
                                       salt=str(salt),
                                       N=1024,
                                       r=1,
                                       p=1,
                                       dkLen=32)
                if HMAC.new(key=str(hashed.encode('hex')), msg=request["data"]["rsa_pub"],
                            digestmod=mode).hexdigest() != request['data']['hmac']:
                    self.server_con.phase = 1
                    self.server_con.state = NOT_CONNECTED
                    return
                self.server_con.sv_rsa_pub = request["data"]["rsa_pub"]
            else:
                print colored("if we get here we r fruked", "red")
        else:
            return
        print colored("Connected to server", "green")
        self.server_con.state = CONNECTED

    def handlerefresh(self, request):
        if self.server_con.state == REFRESHING:
            self.tmp.refresh_buffer = self.server_con.refresh_buffer
            self.tmp.diffie_utils.other_pub = request['data']['pub']
            self.tmp.sv_rsa_pub = request['data']['rsa_pub']
            self.tmp.diffie_utils.shared_key = pow(self.tmp.diffie_utils.otherpub,
                                            self.tmp.diffie_utils.private,
                                            self.tmp.diffie_utils.prime)
            self.server_con = copy.deepcopy(self.tmp)
            self.server_con.state = CONNECTED
            for request in self.server_con.refresh_buffer:
                self.send(request)

    def handledisconnect(self, req):
        print colored(self.lst_clients[req["src"]].name, "blue") + colored(" disconnected", "red")
        cid = self.lst_clients[req["src"]].cid
        name = self.lst_clients[req["src"]].name
        del self.lst_clients[req["src"]]
        self.lst_clients[req["src"]] = Friend()
        self.lst_clients[req["src"]].cid = cid
        self.lst_clients[req["src"]].name = name

    def generateack(self, request):
        ack = { "type" : "secure",
                "payload": {
                    "type": "ack",
                    "topic": request['payload']['type'],
                    "data": {
                            }
                        }
                }
        if 'src' in request['payload']:
            ack['payload']['src'] = self.cid
            ack['payload']['dst'] = request['payload']['src']
            if request["payload"]["type"] != "client-connect":
                ack['payload']['data']['cl_ID'] = request['payload']["data"]['ID']
            else:
                ack["payload"]["phase"] = request["payload"]["phase"]
        elif 'ID' in request['payload']:
            print request['payload']['ID']
            ack['payload']['data']['ID'] = request['payload']['ID']
        if 'com_ID' in request["payload"]["data"]:
            ack['payload']['data']['com_ID'] = request['payload']['data']['com_ID']
        return ack

    def handlerequest(self, request):
        """Handle a request from a client socket.
        """
        try:
            try:
                req = json_loads_byteified(request)
            except:
                print sys.exc_info()
                return

            if not isinstance(req, dict):
                return

            if 'type' not in req:
                return

            self.server_con.count += 1
            if req['type'] == 'ack':
                return

            if req['type'] == 'connect':
                if req["ID"] != self.server_con.last_received+1:
                    print self.server_con.last_received+1
                    print req["ID"]
                    print colored("message out of order from server","red")
                    return
                self.server_con.last_received+=1
                sa_data = UNKNOWN
                signed = UNKNOWN
                if req["phase"] >= 3:
                    if "sa_data" in req.keys():
                        sa_data = req["sa_data"]
                        del req["sa_data"]
                    signed = req['signed']
                    del req['signed']
                    if not CC.verify_svsignature(self.server_con.cert, base64.b64decode(signed), json.dumps(req, sort_keys=True)):
                        print colored("unvalid signature server->client on phase:", "red") + colored(str(req["phase"]),"yellow")
                        return
                if req["phase"] >= 5:
                    if not Utils.validate_HMAC(req,self.server_con.cipher, sa_data, self.server_con.diffie_utils.shared_key):
                        print colored("unvalid HMAC server->client on phase:", "red") + colored(str(req["phase"]),"yellow")
                        return

                self.handleconnect(req)
                return

            if req['type'] == 'secure':
                #obj, cipher, diffie_shared
                sa_data = req["sa_data"]
                del req["sa_data"]
                signed = req['signed']
                del req['signed']
                if not CC.verify_svsignature(self.server_con.cert, base64.b64decode(signed), json.dumps(req, sort_keys=True)):
                    print "invalid server signature"
                    return

                if not Utils.validate_HMAC(req,self.server_con.cipher, sa_data, self.server_con.diffie_utils.shared_key):
                    print "invalid HMAC client<-server"
                    return
                req['payload'] = Utils.decipher(cipher=self.server_con.cipher, priv_sym=self.server_con.my_rsa_priv,
                                                diffie_shared=self.server_con.diffie_utils.shared_key, ciphered_json=req['payload'])
                ID = req["payload"]["ID"]
                del req["payload"]["ID"]
                if 'dst' in req['payload'].keys() and "phase" not in req['payload']:
                    target = req['payload']['src']
                    if target not in self.lst_clients.keys():
                        return
                    cl = self.lst_clients[target]
                    sa_data = req['payload']["sa_data"]
                    del req['payload']["sa_data"]
                    signed = req['payload']['signed']
                    del req['payload']['signed']

                    if not CC.verifySignature(cl.cert, json.dumps(req['payload'],sort_keys=True), base64.b64decode(signed)):
                        print "unvalid signature client->client"
                        return

                    if not Utils.validate_HMAC(req['payload'],cl.cipher, sa_data, cl.diffie_utils.shared_key):
                        print "invalid HMAC client<-client"
                        return
                    #now we decrypt the message
                    req['payload']['data'] = Utils.decipher(cipher=cl.cipher, priv_sym=cl.my_rsa_priv,
                                                            diffie_shared=cl.diffie_utils.shared_key,
                                                            ciphered_json=json.dumps(req['payload']['data']))
                    #check the order of clear text message
                    if req["payload"]["data"]["ID"] != self.lst_clients[target].last_received+1:
                        print colored("message out of order from " + str(target))
                        return
                    self.lst_clients[target].last_received+=1


                if ID != self.server_con.last_received+1:
                    print self.server_con.last_received+1
                    print ID
                    print colored("message out of order from server","red")
                    return
                self.server_con.last_received+=1

                if req["payload"]["type"] == "ack":
                    if 'dst' in req["payload"]:
                        target = req['payload']['src']
                        cl = self.lst_clients[target]
                    if req["payload"]["topic"] == "client-com":
                        print colored(cl.name + " received message with nr: " + str(req["payload"]["data"]["com_ID"]))
                        if cl.msg_count == MAX_MSG_COUNT:
                            self.refresh(cl)
                        return

                    if req["payload"]["topic"] == "failed_client-com":
                            self.lst_clients[req["payload"]["data"]["dst"]].message_counter-=1
                            self.lst_clients[req["payload"]["data"]["dst"]].com_counter-=1
                            return
                    if req["payload"]["topic"] == "client-connect":
                        print colored(self.lst_clients[target].name + " has received our connect request with phase: " + str(req["payload"]['phase']),"blue")
                        if req["payload"]["phase"] == 6:
                            self.lst_clients[target].cid = req["payload"]['src']
                            self.lst_clients[target].phase = req["payload"]['phase']
                            self.lst_clients[target].state = CONNECTED
                            print colored("client connected: ", "green") + colored(cl.name, "cyan")
                            print colored("in the machine:" ,"green") + colored(self.lst_clients[target].machine,"cyan")

                        return

                    if req["payload"]["topic"] == "list" and not "src" in req["payload"]:
                        print colored("the server has received our list request","blue")
                        if self.lststate != WAITING:
                            print colored("we received a list ack but we're not expecting!", "yellow")
                            return
                        self.lststate = ACKED
                        if self.lstbuffer is not None:
                            self.handlelist(self.lstbuffer)
                            self.lstbuffer = None
                        return
                    return

                #TODO FOR NOW STAYS THIS WAY
                if req["payload"]["type"] not in ["client-disconnect", "ack"]:
                    ack = self.generateack(req)
                    self.send(ack)

                if req["payload"]["type"] == "list":
                    if self.lststate == ACKED:
                        self.handlelist(req)
                        self.lststate = IDLE
                    else:
                        # the sv did not ack our list request
                        print colored("We got a list answer without the server"
                                      "Ack our request", "yellow")
                    return

                elif req["payload"]["type"] == "refresh":
                    self.handlerefresh(req['payload'])

                elif req["payload"]["type"] == "client-com":
                    self.handlemessage(req["payload"])

                elif req["payload"]["type"] == "client-connect":
                    sa_data = UNKNOWN
                    signed = UNKNOWN
                    target = req['payload']['src']
                    if req["payload"]["phase"] >= 3:
                        cl = self.lst_clients[target]
                        if "sa_data" in req["payload"].keys():
                            sa_data = req["payload"]["sa_data"]
                            del req["payload"]["sa_data"]

                        signed = req["payload"]['signed']
                        del req["payload"]['signed']
                        if not CC.verifySignature(cl.cert, json.dumps(req["payload"],sort_keys=True), base64.b64decode(signed)):
                            print colored("unvalid signature client->client on phase:", "red") + colored(str(req["payload"]["phase"]),"yellow")
                            return
                    if req["payload"]["phase"] >= 5:

                        if not Utils.validate_HMAC(req["payload"],cl.cipher, sa_data, cl.diffie_utils.shared_key):
                            print colored("unvalid HMAC client->client on phase:", "red") + colored(str(req["payload"]["phase"]),"yellow")
                            return
                    self.handleclientconnect(req["payload"])

                elif req["payload"]["type"] == "client-disconnect":
                    self.handledisconnect(req["payload"])
                else:
                    return
        except Exception, e:
            print e.message
            print traceback.print_exc()
            print colored("Could not handle request", "red")

    def handlelist(self, req):
        if self.lststate != ACKED:
            print colored("we got a list response but no ack, waiting for ack", "yellow")
            self.lstbuffer = req
            return
        clients = req["payload"]["data"]
        if len(clients) == 1:
            if self.lstsilence != 1:
                print colored("There are no other clients except yourself!", "red")
            return
        if self.lstsilence != 1:
            print colored("loaded client list", "green")
            print colored("ID         NAME         LEVEL", "magenta")
        else:
            print colored("refreshed client list", "green")
        cl = {}
        for c in clients:
            if c["id"] != str(self.cid):
                cl[c["id"]] = c["id"]
                if self.lst_clients.get(c["id"]) is None:
                    self.lst_clients[c["id"]] = Friend()
                self.lst_clients[c["id"]].cid = c["id"]
                self.lst_clients[c["id"]].name = c["name"]
                self.lst_clients[c["id"]].level = c["level"]
                if self.lstsilence != 1:
                    print colored(str(c), "yellow")

        keys = cl.viewkeys() & self.lst_clients.viewkeys()
        for key in self.lst_clients.keys():
            if key not in keys:
                del self.lst_clients[key]
        self.lstsilence = 0

    def format_secure(self, message):
        message['payload'] = Utils.cipher(cipher=self.server_con.cipher, pub_sym=self.server_con.sv_rsa_pub,
                                          diffie_shared=self.server_con.diffie_utils.shared_key,
                                          message=json.dumps(message['payload']))
        return message

    def format_client(self, client, message):
        message['payload']['data'] = Utils.cipher(cipher=client.cipher, pub_sym=client.friend_rsa_pub,
                                                  diffie_shared=client.diffie_utils.shared_key,
                                                  message=json.dumps(message['payload']['data']))
        return message

    def handleclientconnect(self, request):
        if not all(k in request.keys() for k in ("type", "src", "dst", "data", "ciphers", "phase")):
            print colored("Connect message with missing fields", "yellow")
            return
        msg = {"type": 'secure',
               "payload": {'type': 'client-connect',
                           'phase': request['phase'] + 1,
                           'ciphers': request['ciphers'],
                           'dst': request['src'],
                           'src': request['dst'],
                           'data': {
                               "df_pr_root": "",
                               "modulus_prime": "",
                               "pub": "",
                               "rsa_pub": "",
                               "hmac": "",
                               "salt": ""
                           }
                           }
               }
        target = request['src']
        if target == self.cid:
            target = request['dst']

        if self.lst_clients.get(request['src']) is None:
            self.lst_clients[target] = Friend()

        if request['phase'] == -1:
            self.lst_clients[target].phase = 1
            self.lst_clients[target].state = NOT_CONNECTED
            print colored("Client cant connect", "red")
            return
        if set(self.supportedciphers).isdisjoint(request['ciphers']):
            msg['payload']['phase'] = -1
            self.lst_clients[target].phase = 1
            self.lst_clients[target].state = NOT_CONNECTED
            self.send(msg)
            print colored("client cant connect", "red")
            return

        if len(request['ciphers']) > 1:
            for cipher in request['ciphers']:
                if cipher in self.supportedciphers:
                    msg['payload']['ciphers'] = [cipher]
                    break

        if self.lst_clients[target].state == CONNECTED:
            print colored("client already connected", "yellow")
            return

        self.lst_clients[target].phase = request['phase'] + 1
        if self.debug and request['ciphers'][0] == "NONE":
            if request['phase'] == 1:
                msg["name"] = self.name
                self.send(msg)
            self.lst_clients[target].cid = request['src']
            self.lst_clients[target].name = request['name']
            self.lst_clients[target].data = request['data']
            self.lst_clients[target].cipher = request['ciphers'][0]
            self.lst_clients[target].phase = request['phase']
            self.lst_clients[target].state = CONNECTED
            print colored("client connected: ", "green") + colored(self.lst_clients[target].name, "cyan")
            return

        (key_agr, asym, sym, hashm) = request['ciphers'][0].split("_")
        if key_agr in ['DHE'] and asym in ['RSA'] and sym in ["AES128", "AES256"] and hashm in ['SHA256', 'SHA512']:
            mode = SHA256
            if hashm == "SHA512":
                mode = SHA512
            if request['phase'] == 1:
                self.lst_clients[target].name = request['name']
                self.lst_clients[target].machine = request["data"]["machine_id"]
                self.lst_clients[target].cid = request["src"]
                self.lst_clients[target].cert = base64.b64decode(request["data"]['cert'])
                msg ["payload"]["data"]["machine_id"] = machine_fingerprint()
                msg['payload']["data"]['cert'] = base64.b64encode(self.cert)
                msg['payload']["data"]['clg'] = base64.b64encode(self.lst_clients[target].clg)
                msg['payload']['name'] = self.name
                print colored("connect at phase: " +  str(msg["payload"]['phase']-1),"green")
                print colored("connect proceed with phase: " +  str(msg["payload"]['phase']),"green")
                self.send(msg)
                return
            elif request['phase'] == 2:
                #<new>
                self.lst_clients[target].name = request['name']
                self.lst_clients[target].machine = request["data"]["machine_id"]
                self.lst_clients[target].cid = request["src"]
                self.lst_clients[target].cert = base64.b64decode(request["data"]['cert'])
                self.lst_clients[target].cipher = request['ciphers'][0]
                if not CC.validate_cert(self.lst_clients[target].cert):
                    print colored("not valid cert", "red")
                    msg['payload']['phase'] = -1
                    self.lst_clients[target].phase = 1
                    self.lst_clients[target].state = NOT_CONNECTED
                    self.send(msg)
                    print colored("client cant connect", "red")
                    return
                signed, self.lst_clients[target].session = CC.sign(base64.b64decode(request["data"]['clg']),self.lst_clients[target].session, self.slot)
                msg['payload']["data"]['signed'] = base64.b64encode(signed)
                msg['payload']["data"]['clg'] = base64.b64encode(self.lst_clients[target].clg)
                msg['payload']["data"]['cert'] = base64.b64encode(self.cert)
                #</new>
                msg['payload']['phase'] = self.lst_clients[target].phase
                msg['payload']['data']['pub'] = self.lst_clients[target].diffie_utils.my_pub
                msg['payload']['data']['modulus_prime'] = self.lst_clients[target].diffie_utils.prime
                msg['payload']['data']['df_pr_root'] = self.lst_clients[target].diffie_utils.pr_root
                print colored("connect at phase: " +  str(msg["payload"]['phase']-1),"green")
                print colored("connect proceed with phase: " +  str(msg["payload"]['phase']),"green")
                self.send(msg)
                return
            elif request['phase'] == 3:
                #<new>
                self.lst_clients[target].cipher = request['ciphers'][0]
                self.lst_clients[target].cert = base64.b64decode(request["data"]['cert'])
                if not CC.validate_cert(self.lst_clients[target].cert):
                    print colored("not valid cert", "red")
                    msg['payload']['phase'] = -1
                    self.lst_clients[target].phase = 1
                    self.lst_clients[target].state = NOT_CONNECTED
                    self.send(msg)
                    print colored("client cant connect", "red")
                    return
                signed, self.lst_clients[target].session = CC.sign(base64.b64decode(request["data"]['clg']),self.lst_clients[target].session, self.slot)
                ver = CC.verifySignature(self.lst_clients[target].cert,
                                                self.lst_clients[target].clg,
                                                base64.b64decode(request["data"]['signed']))
                if not ver:
                    print colored("client->client signature failed","red")
                    msg['payload']['phase'] = -1
                    self.lst_clients[target].phase = 1
                    self.lst_clients[target].state = NOT_CONNECTED
                    self.send(msg)
                    print colored("client cant connect", "red")
                    return
                msg['payload']["data"]['signed'] = base64.b64encode(signed)
                #</new>
                self.lst_clients[target].diffie_utils.prime = request["data"]["modulus_prime"]
                self.lst_clients[target].diffie_utils.pr_root = request["data"]["df_pr_root"]
                self.lst_clients[target].diffie_utils.other_pub = request["data"]["pub"]
                self.lst_clients[target].diffie_utils.my_pub = pow(request["data"]["df_pr_root"],
                                                      self.lst_clients[target].diffie_utils.private,
                                                      request["data"]["modulus_prime"]
                                                      )
                self.lst_clients[target].diffie_utils.shared_key = pow(request["data"]["pub"],
                                                         self.lst_clients[target].diffie_utils.private,
                                                         request["data"]["modulus_prime"]
                                                         )
                msg['payload']['phase'] = request['phase'] + 1
                msg['payload']['data']['pub'] = self.lst_clients[target].diffie_utils.my_pub
                msg['payload']['data']['df_pr_root'] = request["data"]["df_pr_root"]
                msg['payload']['data']['modulus_prime'] = request["data"]["modulus_prime"]
                print colored("connect at phase: " +  str(msg["payload"]['phase']-1),"green")
                print colored("connect proceed with phase: " +  str(msg["payload"]['phase']),"green")
                self.send(msg)
                return

            elif request['phase'] == 4:
                if not CC.verifySignature(self.lst_clients[target].cert,
                                                self.lst_clients[target].clg,
                                                base64.b64decode(request["data"]['signed'])):
                    print colored("client->client signature failed","red")
                    msg['payload']['phase'] = -1
                    self.lst_clients[target].phase = 1
                    self.lst_clients[target].state = NOT_CONNECTED
                    self.send(msg)
                    print colored("client cant connect", "red")
                    return
                if self.lst_clients[target].diffie_utils.pr_root == request["data"]["df_pr_root"] and \
                                self.lst_clients[target].diffie_utils.prime == request["data"]["modulus_prime"]:
                    self.lst_clients[target].diffie_utils.other_pub = request["data"]["pub"]
                    self.lst_clients[target].diffie_utils.shared_key = pow(request["data"]["pub"],
                                                             self.lst_clients[target].diffie_utils.private,
                                                             request["data"]["modulus_prime"])
                    salt = random.getrandbits(64)
                    hashed = pyscrypt.hash(password=str(self.lst_clients[target].diffie_utils.shared_key),
                                           salt=str(salt),
                                           N=1024,
                                           r=1,
                                           p=1,
                                           dkLen=32)
                    msg['payload']['phase'] = self.lst_clients[target].phase
                    msg['payload']['data']['rsa_pub'] = self.lst_clients[target].my_rsa_pub
                    msg['payload']['data']['hmac'] = HMAC.new(key=str(hashed.encode('hex')),
                                                              msg=self.lst_clients[target].my_rsa_pub,
                                                              digestmod=mode).hexdigest()
                    msg['payload']['data']['salt'] = salt
                    print colored("connect at phase: " +  str(msg["payload"]['phase']-1),"green")
                    print colored("connect proceed with phase: " +  str(msg["payload"]['phase']),"green")
                    self.send(msg)

                return

            elif request['phase'] == 5:
                salt = request['data']['salt']
                hashed = pyscrypt.hash(password=str(self.lst_clients[target].diffie_utils.shared_key),
                                       salt=str(salt),
                                       N=1024,
                                       r=1,
                                       p=1,
                                       dkLen=32)

                if HMAC.new(key=str(hashed.encode('hex')), msg=request["data"]["rsa_pub"],
                            digestmod=mode).hexdigest() != request['data']['hmac']:
                    msg['payload']['phase'] = -1
                    self.lst_clients[target].phase = 1
                    self.lst_clients[target].state = NOT_CONNECTED
                    self.send(msg)
                    return
                self.lst_clients[target].friend_rsa_pub = request['data']['rsa_pub']
                salt = random.getrandbits(64)
                hashed = pyscrypt.hash(password=str(self.lst_clients[target].diffie_utils.shared_key),
                                       salt=str(salt),
                                       N=1024,
                                       r=1,
                                       p=1,
                                       dkLen=32)
                msg['payload']['phase'] = request['phase'] + 1
                msg['payload']['data']['rsa_pub'] = self.lst_clients[target].my_rsa_pub
                msg['payload']['data']['hmac'] = HMAC.new(key=str(hashed.encode('hex')),
                                                          msg=msg['payload']['data']['rsa_pub'],
                                                          digestmod=mode).hexdigest()
                msg['payload']['data']['salt'] = salt
                print colored("connect at phase: " +  str(msg["payload"]['phase']-1),"green")
                print colored("connect proceed with phase: " +  str(msg["payload"]['phase']),"green")
                self.send(msg)
            elif request['phase'] == 6:
                salt = request['data']['salt']
                hashed = pyscrypt.hash(password=str(self.lst_clients[target].diffie_utils.shared_key),
                                       salt=str(salt),
                                       N=1024,
                                       r=1,
                                       p=1,
                                       dkLen=32)
                if HMAC.new(key=str(hashed.encode('hex')), msg=request["data"]["rsa_pub"],
                            digestmod=mode).hexdigest() != request['data']['hmac']:
                    msg['payload']['phase'] = -1
                    self.lst_clients[request['src']].phase = 1
                    self.lst_clients[request['src']].state = NOT_CONNECTED
                    self.send(msg)
                    return
                self.lst_clients[target].friend_rsa_pub = request["data"]["rsa_pub"]
                self.lst_clients[target].cid = request['src']
                self.lst_clients[target].phase = request['phase']
                self.lst_clients[target].state = CONNECTED
                print colored("client connected: ", "green") + colored(self.lst_clients[target].name, "cyan")
                print colored("in the machine:" ,"green") + colored(self.lst_clients[target].machine,"cyan")
            else:
                return
        else:
            msg['payload']['phase'] = -1
            self.lst_clients[request['src']].phase = 1
            self.lst_clients[request['src']].state = NOT_CONNECTED
            self.send(msg)
            return

    def handlemessage(self, req):
        if self.lst_clients[req["src"]].state == CONNECTED:
            msg = colored(str(req["data"]["com_ID"]) + " "+ self.lst_clients[req["src"]].name + ": ", "cyan") + colored(req["data"]["msg"], "white")
            print msg

    def stop(self):
        for key in self.lst_clients.keys():
            if self.lst_clients[key].state == CONNECTED:
                self.client_disconnect(self.lst_clients[key])
        exit()


def print_menu():
    print colored("____________________________", "magenta")
    print colored("|          IMSEC           |", "magenta")
    print colored("|'/l'-> list clients       |", "magenta")
    print colored("|'/cc'-> Connect to client |", "magenta")
    print colored("|'/dc'-> disconnect client |", "magenta")
    print colored("|'/m' -> Message client    |", "magenta")
    print colored("|", "magenta") + colored("'/e'-> close              ", "red") + colored("|", "magenta")
    print colored("|__________________________|", "magenta")

def machine_fingerprint():
    f = open("/sys/class/dmi/id/modalias", "r")
    modalias =  f.read()
    f.close()
    sha = SHA256.new()
    sha.update(modalias)
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        sha.update(str(addrs[netifaces.AF_LINK]))
    return sha.hexdigest()

def menu(slot=0):
    c = Client(slot)
    # substituir id por getmac('eth0') no futuro
    c.connect()
    switch = {
        '/l': lambda: c.lst(),
        '/cc': lambda: c.connect_client(),
        '/dc': lambda: c.client_disconnect(),
        '/m': lambda: c.sendmessage(),
        '/e': lambda: c.stop()
    }
    print_menu()

    while True:
        try:
            rsocks = select([c.client_socket, sys.stdin, ], [], [])[0]
            for sock in rsocks:
                if sock == c.client_socket:
                    # Informacao recebida no socket
                    data = c.client_socket.recv(BUFSIZE)
                    reqs = c.parsereqs(data)
                    for req in reqs:
                        c.handlerequest(req)
                elif sock == sys.stdin:
                    # Informacao recebida do teclado
                    data = sys.stdin.readline().rstrip()
                    if data in switch.keys():
                        switch[data]()
                    else:
                        print colored("pick a valid option plis", "yellow")
                    print_menu()
        except KeyboardInterrupt:
            c.stop()
            try:
                print colored("Press CTRL-C again within 2 sec to quit", "yellow")
                time.sleep(2)
            except KeyboardInterrupt:
                print colored("CTRL-C pressed twice: Quitting!", "red")
                break
        except Exception, e:
            print e.message


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--slot', dest='slot', type=int, default=0)
    args = parser.parse_args()
    menu(args.slot)
