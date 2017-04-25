# encoding: utf-8
#
# Alvaro.martins@ua.pt
# DETI UA 2016
# vim setings:
# :set expandtab ts=4
import copy
import socket
from select import select
import sys
import argparse
from termcolor import colored
#
import traceback
import time
from security import *

#


UNKNOWN = None

BUFSIZE = 512 * 1024
MAX_BUFSIZE = 64 * 1024
# sv states
CONNECTED = 1
WAITING_CONNECTION = 2
NOT_CONNECTED = 3
REFRESHING = 4
# req states
IDLE = 1
WAITING = 2

# 5 para debug
MAX_MSG_COUNT = 7
MAX_SV_MESSAGE = 30


class ServerConnection:
    state = NOT_CONNECTED
    cipher = UNKNOWN
    df_private = random.randint(0, 256)
    df_prime = random.choice(primes(df_private))
    df_pr_root = random.choice(primitive_root(df_prime))
    df_pub = pow(df_pr_root, df_private, df_prime)
    sv_pub = UNKNOWN
    df_shared = UNKNOWN
    refresh_buffer = []
    phase = 1
    count = 0
    sv_rsa_pub = UNKNOWN
    my_rsa_key = RSA.generate(2048)
    my_rsa_priv = my_rsa_key.exportKey()
    my_rsa_pub = my_rsa_key.publickey().exportKey()


class Friend:
    name = ""
    cid = UNKNOWN
    cipher = UNKNOWN
    state = NOT_CONNECTED
    phase = 1
    msg_count = 0
    level = UNKNOWN
    friend_rsa_pub = UNKNOWN
    df_private = random.randint(0, 256)
    df_prime = random.choice(primes(df_private))
    df_pr_root = random.choice(primitive_root(df_prime))
    df_pub = pow(df_pr_root, df_private, df_prime)
    friend_pub = UNKNOWN
    df_shared = UNKNOWN
    my_rsa_key = RSA.generate(2048)
    my_rsa_priv = my_rsa_key.exportKey()
    my_rsa_pub = my_rsa_key.publickey().exportKey()


class Client:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))
    ccnt = {}
    bufin = ""
    lstsilence = 0
    name = ""
    cid = UNKNOWN
    lststate = IDLE
    server_con = ServerConnection()
    tmp = UNKNOWN
    lst_clients = {}

    def __init__(self, name, cid, debug=False):
        self.debug = debug
        self.supportedciphers = ['DHE_RSA_AES256_SHA512',
                                 'DHE_RSA_AES256_SHA256',
                                 'DHE_RSA_AES128_SHA512',
                                 'DHE_RSA_AES128_SHA256']
        if self.debug:
            self.supportedciphers = ["NONE"]
        self.name = name
        self.cid = cid

    def send(self, obj):
        if self.server_con.state == REFRESHING:
            self.server_con.refresh_buffer += [obj]
            return
        if obj['type'] == 'secure':
            if 'dst' in obj['payload'] and obj['payload']['type'] != 'client-connect':
                obj = self.format_client(self.lst_clients[obj['payload']['dst']], obj)
            obj = self.format_secure(obj)
        try:
            self.client_socket.send(json.dumps(obj) + "\n\n")
            if self.server_con.count > MAX_SV_MESSAGE and not self.debug:
                self.server_con.count = 0
                self.refresh_sv()

        except:
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
                "data": msg
            }
        }
        self.send(data)
        self.lst_clients[dst.cid].msg_count += 1
        if self.lst_clients[dst.cid].msg_count == MAX_MSG_COUNT:
            self.refresh(dst)
        print colored("sent to " + self.lst_clients[dst.cid].name + ": ", "cyan") + colored(msg, "white")

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
                    "df_pr_root": self.tmp.df_pr_root,
                    "modulus_prime": self.tmp.df_prime,
                    "pub": self.tmp.df_pub,
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
                "phase": 1,
                "ciphers": self.supportedciphers,
                "data": "hue"
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
                               "data": "None for now"}
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
                "data": {
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
                msg['data']['df_pr_root'] = self.server_con.df_pr_root
                msg['data']['modulus_prime'] = self.server_con.df_prime
                msg['data']['pub'] = self.server_con.df_pub
                self.send(msg)
                return
            elif request['phase'] == 4:
                if self.server_con.df_pr_root == request["data"]["df_pr_root"] and \
                                self.server_con.df_prime == request["data"]["modulus_prime"]:
                    self.server_con.sv_pub = request["data"]["pub"]
                    self.server_con.df_shared = pow(self.server_con.sv_pub,
                                                    self.server_con.df_private,
                                                    self.server_con.df_prime)
                    salt = random.getrandbits(64)
                    hashed = pyscrypt.hash(password=str(self.server_con.df_shared),
                                           salt=str(salt),
                                           N=1024,
                                           r=1,
                                           p=1,
                                           dkLen=32)

                    msg['data']["rsa_pub"] = self.server_con.my_rsa_pub
                    msg['data']['hmac'] = HMAC.new(key=str(hashed.encode('hex')),
                                                   msg=self.server_con.my_rsa_pub,
                                                   digestmod=mode).hexdigest()
                    msg['data']['salt'] = salt
                    self.send(msg)

                return
            elif request['phase'] == 6:
                salt = request['data']['salt']
                hashed = pyscrypt.hash(password=str(self.server_con.df_shared),
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
        self.server_con.cipher = request['ciphers'][0]

    def handlerefresh(self, request):
        self.tmp.refresh_buffer = self.server_con.refresh_buffer
        self.tmp.sv_pub = request['data']['pub']
        self.tmp.sv_rsa_pub = request['data']['rsa_pub']
        self.tmp.df_shared = pow(self.tmp.sv_pub, self.tmp.df_private, self.tmp.df_prime)
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

            if req['type'] == 'ack':
                return
            self.server_con.count += 1
            if req['type'] == 'connect':
                self.handleconnect(req)
                return

            if req['type'] == 'secure':

                req['payload'] = Utils.decipher(cipher=self.server_con.cipher, priv_sym=self.server_con.my_rsa_priv,
                                                diffie_shared=self.server_con.df_shared, ciphered_json=req['payload'])
                if req['payload']['type'] in ['client-com']:
                    target = req['payload']['src']
                    cl = self.lst_clients[target]
                    req['payload']['data'] = Utils.decipher(cipher=cl.cipher, priv_sym=cl.my_rsa_priv,
                                                            diffie_shared=cl.df_shared,
                                                            ciphered_json=json.dumps(req['payload']['data']))
                if req["payload"]["type"] == "list":
                    if self.lststate == WAITING:
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

                elif req["payload"]["type"] == "ack":
                    # TODO mensagens para próxima entrega
                    pass
                elif req["payload"]["type"] == "client-connect":
                    self.handleclientconnect(req["payload"])

                elif req["payload"]["type"] == "client-disconnect":
                    self.handledisconnect(req["payload"])

                else:
                    return
        except Exception, e:
            print e.message
            print colored("Could not handle request", "red")

    def handlelist(self, req):
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
            if int(c["id"]) != self.cid:
                cl[c["id"]] = c["id"]
                if self.lst_clients.get(c["id"]) is None:
                    self.lst_clients[c["id"]] = Friend()
                self.lst_clients[c["id"]].cid = c["id"]
                self.lst_clients[c["id"]].name = c["name"]
                self.lst_clients[c["id"]].level = c["level"]
                if self.lstsilence != 1:
                    print colored(str(c), "blue")

        keys = cl.viewkeys() & self.lst_clients.viewkeys()
        for key in self.lst_clients.keys():
            if key not in keys:
                del self.lst_clients[key]
        self.lstsilence = 0

    def format_secure(self, message):
        message['payload'] = Utils.cipher(cipher=self.server_con.cipher, pub_sym=self.server_con.sv_rsa_pub,
                                          diffie_shared=self.server_con.df_shared,
                                          message=json.dumps(message['payload']))
        return message

    def format_client(self, client, message):
        message['payload']['data'] = Utils.cipher(cipher=client.cipher, pub_sym=client.friend_rsa_pub,
                                                  diffie_shared=client.df_shared,
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
            self.lst()
            self.lstsilence = 1
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
                self.send(msg)
            self.lst_clients[target].cid = request['src']
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
                self.send(msg)
                return
            elif request['phase'] == 2:
                msg['payload']['phase'] = self.lst_clients[target].phase
                msg['payload']['data']['pub'] = self.lst_clients[target].df_pub
                msg['payload']['data']['modulus_prime'] = self.lst_clients[target].df_prime
                msg['payload']['data']['df_pr_root'] = self.lst_clients[target].df_pr_root
                self.send(msg)
                return

            elif request['phase'] == 3:
                self.lst_clients[target].df_prime = request["data"]["modulus_prime"]
                self.lst_clients[target].df_pr_root = request["data"]["df_pr_root"]
                self.lst_clients[target].friend_pub = request["data"]["pub"]
                self.lst_clients[target].df_pub = pow(request["data"]["df_pr_root"],
                                                      self.lst_clients[target].df_private,
                                                      request["data"]["modulus_prime"]
                                                      )
                self.lst_clients[target].df_shared = pow(request["data"]["pub"],
                                                         self.lst_clients[target].df_private,
                                                         request["data"]["modulus_prime"]
                                                         )
                msg['payload']['phase'] = request['phase'] + 1
                msg['payload']['data']['pub'] = self.lst_clients[target].df_pub
                msg['payload']['data']['df_pr_root'] = request["data"]["df_pr_root"]
                msg['payload']['data']['modulus_prime'] = request["data"]["modulus_prime"]
                print colored("Connecting to: ", "green") + colored(self.lst_clients[target].name)
                self.send(msg)
                return

            elif request['phase'] == 4:
                if self.lst_clients[target].df_pr_root == request["data"]["df_pr_root"] and \
                                self.lst_clients[target].df_prime == request["data"]["modulus_prime"]:
                    self.lst_clients[target].friend_pub = request["data"]["pub"]
                    self.lst_clients[target].df_shared = pow(request["data"]["pub"],
                                                             self.lst_clients[target].df_private,
                                                             request["data"]["modulus_prime"])
                    salt = random.getrandbits(64)
                    hashed = pyscrypt.hash(password=str(self.lst_clients[target].df_shared),
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
                    self.send(msg)

                return

            elif request['phase'] == 5:
                salt = request['data']['salt']
                hashed = pyscrypt.hash(password=str(self.lst_clients[target].df_shared),
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
                hashed = pyscrypt.hash(password=str(self.lst_clients[target].df_shared),
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
                self.send(msg)
            elif request['phase'] == 6:
                salt = request['data']['salt']
                hashed = pyscrypt.hash(password=str(self.lst_clients[target].df_shared),
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
            else:
                return
        else:
            msg['payload']['phase'] = -1
            self.lst_clients[request['src']].phase = 1
            self.lst_clients[request['src']].state = NOT_CONNECTED
            self.send(msg)
            return

        self.lst_clients[target].cid = request['src']
        self.lst_clients[target].data = request['data']
        self.lst_clients[target].cipher = request['ciphers'][0]
        self.lst_clients[target].phase = request['phase']
        self.lst_clients[target].state = CONNECTED
        print colored("client connected: ", "green") + colored(self.lst_clients[target].name, "cyan")

    def handlemessage(self, req):
        if self.lst_clients[req["src"]].state == CONNECTED:
            msg = colored(self.lst_clients[req["src"]].name + ": ", "cyan") + colored(req["data"], "white")
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


def menu(debug=False):
    name = raw_input("client name: ")
    c = Client(name, int("".join([str(random.randint(0, 9)) for i in range(12)])), debug)
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
    parser.add_argument('-d', '--debug', dest='debug', action='store_true')
    args = parser.parse_args()
    menu(args.debug)
