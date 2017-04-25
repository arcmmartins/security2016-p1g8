# encoding: utf-8
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim setings:
# :set expandtab ts=4
import argparse
from socket import *
from select import *
import json
import sys
import os
import time
import logging
from security import *
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from termcolor import colored
from Crypto.Random import random
from Crypto.Hash import HMAC
from DiffieHellmanUtils import DHUtils
from Database_Server import DBUtils
# Server address
HOST = ""  # All available interfaces
PORT = 8080  # The server port
from CCUtils import CCUtils
BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2
CC = CCUtils()
DB = DBUtils()
CHALLENGE_SIZE = 10

UNKNOWN = None

class RSAUtils:
    cl_rsa_pub = None
    my_rsa_key = RSA.generate(2048)
    my_rsa_priv = my_rsa_key.exportKey()
    my_rsa_pub = my_rsa_key.publickey().exportKey()


class Client:
    count = 0

    def __init__(self, socket, addr):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.id = UNKNOWN
        self.sa_data = UNKNOWN
        self.level = 0
        self.message_counter = 1
        self.last_received = 0
        self.state = STATE_NONE
        self.name = "Unknown"
        self.agreedcipher = UNKNOWN
        self.tmpdf = UNKNOWN
        self.challenge = "".join([str(random.randint(0, 9)) for i in range(CHALLENGE_SIZE)])
        self.tmprsa = UNKNOWN
        self.diffie_utils = DHUtils()
        self.RSAutils = RSAUtils()
        self.CCCert = UNKNOWN

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s name:%s level:%d state:%d)" % (
            self.id, str(self.addr), self.name, self.level, self.state)

    def asDict(self):
        return {'name': self.name, 'id': self.id, 'level': self.level}

    def setState(self, state):
        if state not in [STATE_CONNECTED, STATE_NONE, STATE_DISCONNECTED]:
            return

        self.state = state

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            logging.error("Client (%s) buffer exceeds MAX BUFSIZE. %d > %d",
                          (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split(TERMINATOR)
        self.bufin = reqs[-1]
        if len(self.bufin) > 1:
            print colored("BUFIN: " + self.bufin, "green")
        return reqs[:-1]

    def send(self, obj):
        if obj['type'] == 'secure':
            obj['payload']['ID'] = self.message_counter
            self.message_counter+=1
            cipher = self.agreedcipher
            dh = self.diffie_utils.shared_key
            obj['payload'] = Utils.cipher(cipher=cipher, pub_sym=self.RSAutils.cl_rsa_pub,
                                   diffie_shared=dh, message=obj['payload'])
            HMAC = Utils.attach_HMAC(obj,cipher,dh)
            SIGNED = CC.sign_sv(json.dumps(obj,sort_keys=True))
            obj = HMAC
            obj['signed'] = base64.b64encode(SIGNED)
        elif obj["type"] == "connect":
            obj["ID"] = self.message_counter
            self.message_counter+=1
            if obj["phase"] >= 3:
                SIGNED = CC.sign_sv(json.dumps(obj,sort_keys=True))
                if obj["phase"] >=5:
                    cipher = self.agreedcipher
                    dh = self.diffie_utils.shared_key
                    HMAC = Utils.attach_HMAC(obj,cipher,dh)
                else:
                    HMAC = obj
                obj = HMAC
                obj["signed"] = base64.b64encode(SIGNED)

        try:
            self.bufout += json.dumps(obj) + "\n\n"
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)", self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        logging.info("Client.close(%s)", self)
        try:
            # Shutdown will fail on a closed socket...
            # self.socket.shutdown(SHUT_RDWR)
            self.socket.close()
        except:
            logging.exception("Client.close(%s)", self)

        logging.info("Client Closed")


class ChatError(Exception):
    """This exception should signal a protocol error in a client request.
    It is not a server error!
    It just means the server must report it to the sender.
    It should be dealt with inside handleRequest.
    (It should allow leaner error handling code.)
    """
    pass


def ERROR(msg):
    """Raise a Chat protocol error."""
    raise ChatError(msg)


class Server:
    def __init__(self, host, port, debug=False):
        self.debug = debug
        self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
        self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.ss.bind((host, port))
        self.ss.listen(10)
        self.supportedciphers = ['DHE_RSA_AES128_SHA256', 'DHE_RSA_AES256_SHA256',
                                 'DHE_RSA_AES256_SHA512', 'DHE_RSA_AES128_SHA512']
        if self.debug:
            self.supportedciphers = ["NONE"]
        logging.info("Secure IM server listening on %s", self.ss.getsockname())
        # clients to manage (indexed by socket and by name):
        self.clients = {}  # clients (key is socket)
        self.id2client = {}  # clients (key is id)

        self.cert = CC.getSvCert()

    def stop(self):
        """ Stops the server closing all sockets
        """
        logging.info("Stopping Server")
        try:
            # self.ss.shutdown(SHUT_RDWR)
            self.ss.close()
        except:
            logging.exception("Server.stop")

        for csock in self.clients:
            try:
                self.clients[csock].close()  # Client.close!
            except:
                # this should not happen since close is protected...
                logging.exception("clients[csock].close")

        # If we delClient instead, the following would be unnecessary...
        self.clients.clear()
        self.id2client.clear()

    def addClient(self, csock, addr):
        """Add a client connecting in csock."""
        if csock in self.clients:
            logging.error("Client NOT Added: %s already exists", self.clients[csock])
            return

        client = Client(csock, addr)
        self.clients[client.socket] = client
        logging.info("Client added: %s", client)

    def delClient(self, csock):
        """Delete a client connected in csock."""
        if csock not in self.clients:
            logging.error("Client NOT deleted: %s not found", self.clients[csock])
            return

        client = self.clients[csock]
        assert client.socket == csock, "client.socket (%s) should match key (%s)" % (client.socket, csock)
        if client.id in self.id2client.keys():
            del self.id2client[client.id]
        del self.clients[client.socket]
        client.close()
        logging.info("Client deleted: %s", client)

    def accept(self):
        """Accept a new connection.
        """
        try:
            csock, addr = self.ss.accept()
            self.addClient(csock, addr)
        except:
            logging.exception("Could not accept client")

    def flushin(self, s):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """
        client = self.clients[s]
        data = None
        try:
            data = s.recv(BUFSIZE)
            logging.info("Received data from %s. Message:\n%r", client, data)
        except:
            logging.exception("flushin: recv(%s)", client)
            logging.error("Received invalid data from %s. Closing", client)
            self.delClient(s)
        else:
            if len(data) > 0:
                reqs = client.parseReqs(data)
                for req in reqs:
                    self.handleRequest(s, req)
            else:
                self.delClient(s)

    def flushout(self, s):
        """Write a chunk of data to client.
        This is called whenever client socket is ready to transmit data."""
        if s not in self.clients:
            # this could happen before, because a flushin might have deleted the client
            logging.error("BUG: Flushing out socket that is not on client list! Socket=%s", str(s))
            return

        client = self.clients[s]
        try:
            sent = client.socket.send(client.bufout[:BUFSIZE])
            logging.info("Sent %d bytes to %s. Message:\n%r", sent, client, client.bufout[:sent])
            # print colored(("Sent %d bytes to %s. Message:\n%r", sent, client, client.bufout[:sent]), "blue")
            client.bufout = client.bufout[sent:]  # leave remaining to be sent later
        except:
            logging.exception("flushout: send(%s)", client)
            # logging.error("Cannot write to client %s. Closing", client)
            self.delClient(client.socket)

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + every open client connection)
            rlist = [self.ss] + self.clients.keys()
            # sockets to select for writing: (those that have something in bufout)
            wlist = [sock for sock in self.clients if len(self.clients[sock].bufout) > 0]
            logging.debug("select waiting for %dR %dW %dX", len(rlist), len(wlist), len(rlist))
            (rl, wl, xl) = select(rlist, wlist, rlist)
            logging.debug("select: %s %s %s", rl, wl, xl)

            # Deal with incoming data:
            for s in rl:
                if s is self.ss:
                    self.accept()
                elif s in self.clients:
                    self.flushin(s)
                else:
                    logging.error("Incoming, but %s not in clients anymore", s)

            # Deal with outgoing data:
            for s in wl:
                if s in self.clients:
                    self.flushout(s)
                else:
                    logging.error("Outgoing, but %s not in clients anymore", s)

            for s in xl:
                logging.error("EXCEPTION in %s. Closing", s)
                self.delClient(s)

    def handleRequest(self, s, request):
        """Handle a request from a client socket.
        """
        client = self.clients[s]
        try:
            logging.info("HANDLING message from %s: %r", client, repr(request))

            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'type' not in req:
                return

            if req['type'] == 'ack':
                return  # Ignore for now

            if req['type'] == 'connect':
                client.send({'type': 'ack',
                             'data': 'connect'
                             })
                if req["ID"] != client.last_received+1:
                    logging.warning("Message out of order")
                    return
                client.last_received += 1
                sa_data = UNKNOWN
                signed = UNKNOWN
                if req["phase"] >= 3:
                    if "sa_data" in req.keys():
                        sa_data = req["sa_data"]
                        del req["sa_data"]

                    signed = req['signed']
                    del req['signed']
                    if not CC.verifySignature(client.cert, json.dumps(req,sort_keys=True), base64.b64decode(signed)):
                        print colored("unvalid signature client->server on phase:", "red") + colored(str(req["phase"]),"yellow")
                        return
                if req["phase"] >= 5:
                    if not Utils.validate_HMAC(req,client.agreedcipher, sa_data, client.diffie_utils.shared_key):
                        print colored("unvalid HMAC client->server on phase:", "red") + colored(str(req["phase"]),"yellow")
                        return
                self.processConnect(client, req)

            elif req['type'] == 'secure':
                self.processSecure(client, req)

        except Exception, e:
            logging.exception("Could not handle request")

    def clientList(self, requester):
        """
        Return the client list
        """
        cl = []
        for k in self.clients:
            if requester.level <= self.clients[k].level:
                cl.append(self.clients[k].asDict())
        return cl

    def processConnect(self, sender, request):
        """
        Process a connect message from a client
        """
        if sender.state == STATE_CONNECTED:
            logging.warning("Client is already connected: %s" % sender)
            return

        if not all(k in request.keys() for k in ("name", "ciphers", "phase", "id")):
            logging.warning("Connect message with missing fields")
            return

        if set(self.supportedciphers).isdisjoint(request['ciphers']):
            msg = {'type': 'connect', 'phase': -1, 'ciphers': ['NONE'], "data": {}}
            sender.send(msg)
            return
        msg = {'type': 'connect', 'phase': request['phase'] + 1, 'ciphers': request['ciphers'], "data": {}}
        if len(request['ciphers']) > 1 and not set(self.supportedciphers).isdisjoint(request['ciphers']):
            for cipher in request['ciphers']:
                if cipher in self.supportedciphers:
                    msg['ciphers'] = [cipher]
                    break
            logging.info("Connect continue to phase " + str(msg['phase']))

        # se nao suportarmos as cifras que o client suporta acabamos a tentativa
        if request['ciphers'][0] == "NONE" and self.debug:
            sender.send(msg)
            sender.id = request['id']
            sender.agreedcipher = request['ciphers'][0]
            sender.name = request['name']
            sender.state = STATE_CONNECTED
            self.id2client[request['id']] = sender
            logging.info("Client %s Connected" % request['id'])
            return
        (key_agr, asym, sym, hashm) = request['ciphers'][0].split("_")
        if key_agr in ['DHE'] and asym in ['RSA'] and sym in ["AES128", "AES256"] and hashm in ['SHA256', 'SHA512']:
            mode = SHA256
            if hashm == "SHA512":
                mode = SHA512
            if request['phase'] == 1:
                sender.agreedcipher = request['ciphers'][0]
                sender.cert = base64.b64decode(request['data']['cert'])
                if not CC.validate_cert(sender.cert):
                    print colored("not valid cert", "red")
                msg['data']['clg'] = sender.challenge
                msg['data']['cert'] = base64.b64encode(self.cert)
                sender.send(msg)
                return
            elif request['phase'] == 3:
                sender.diffie_utils.prime = request["data"]["modulus_prime"]
                sender.diffie_utils.pr_root = request["data"]["df_pr_root"]
                sender.diffie_utils.other_pub = request["data"]["pub"]
                sender.diffie_utils.my_pub = pow(sender.diffie_utils.pr_root, sender.diffie_utils.private, sender.diffie_utils.prime)
                sender.diffie_utils.shared_key = pow(sender.diffie_utils.other_pub, sender.diffie_utils.private, sender.diffie_utils.prime)
                msg['data']['pub'] = sender.diffie_utils.my_pub
                msg['data']['df_pr_root'] = request["data"]["df_pr_root"]
                msg['data']['modulus_prime'] = request["data"]["modulus_prime"]
                success =  CC.verifySignature(sender.cert, sender.challenge, base64.b64decode(request['data']['signed']))
                if not success:
                    print colored("invalid signature from client" + str(sender),"red")
                    sender.challenge = "".join([str(random.randint(0, 9)) for i in range(CHALLENGE_SIZE)])
                    return
                msg['data']['signed'] = base64.b64encode(CC.sign_sv(request['data']['clg']))
                sender.challenge = "".join([str(random.randint(0, 9)) for i in range(CHALLENGE_SIZE)])
                sender.send(msg)
                return
            elif request['phase'] == 5:
                salt = request['data']['salt']
                hashed = pyscrypt.hash(password=str(sender.diffie_utils.shared_key),
                                       salt=str(salt),
                                       N=1024,
                                       r=1,
                                       p=1,
                                       dkLen=32)

                if HMAC.new(key=str(hashed.encode('hex')), msg=request["data"]["rsa_pub"],
                            digestmod=mode).hexdigest() != request['data']['hmac']:
                    msg = {'type': 'connect', 'phase': -1, 'ciphers': ['NONE'], "data": {}}
                    sender.send(msg)
                    return
                sender.RSAutils.cl_rsa_pub = request['data']['rsa_pub']

                salt = random.getrandbits(64)
                hashed = pyscrypt.hash(password=str(sender.diffie_utils.shared_key),
                                       salt=str(salt),
                                       N=1024,
                                       r=1,
                                       p=1,
                                       dkLen=32)

                msg['data']['rsa_pub'] = sender.RSAutils.my_rsa_pub
                msg['data']['hmac'] = HMAC.new(key=str(hashed.encode('hex')), msg=sender.RSAutils.my_rsa_pub,
                                               digestmod=mode).hexdigest()
                msg['data']['salt'] = salt
            else:
                return
        else:
            return
        #0->ID 1->NAME 2-> CERT 3-level
        usr = DB.getuser(request["id"])

        if usr != []:
            usr = usr[0]
            if not CC.validate_cert(usr[2]):
                print colored("not valid cert in DB, we must replace", "red")
                namecc , numbercc = CC.get_data_cert(sender.cert)
                if numbercc == request["id"]:
                    DB.updatecert(request["id"], sender.cert)
                else:
                    print colored("imposer trying to pass as " + str(request['id']), "red")
                    #dont connect
                    msg = {'type': 'connect', 'phase': -1, 'ciphers': ['NONE'], "data": {}}
                    sender.send(msg)
                    return

            if sender.cert != usr[2]:
                print colored("imposer trying to pass as " + str(request['id']), "red")
                #dont connect
                msg = {'type': 'connect', 'phase': -1, 'ciphers': ['NONE'], "data": {}}
                sender.send(msg)
                return
            sender.level = int(usr[3])
        else:
            sender.level = random.randint(0,4)
            DB.insertuser([request['id'], request['name'], sender.cert,sender.level])
        sender.send(msg)
        sender.id = request['id']
        sender.name = request['name']
        sender.state = STATE_CONNECTED
        self.id2client[request['id']] = sender
        logging.info("Client %s Connected" % request['id'])

    def processList(self, sender, request):
        """
        Process a list message from a client
        """
        if sender.state != STATE_CONNECTED:
            logging.warning("LIST from disconnected client: %s" % sender)
            return
        sender.send({'type': 'secure',
                     'payload': {'type': 'ack', 'topic': "list"}
                     })
        msg = {'type': 'secure', 'payload': {'type': 'list', 'data': self.clientList(sender)}}
        sender.send(msg)

    def processRefresh(self, sender, request):
        tmpdf = DHUtils()
        tmprsa = RSAUtils()
        tmpdf.cl_pub = request['data']['pub']
        tmpdf.pr_root = request['data']['df_pr_root']
        tmpdf.prime = request['data']['modulus_prime']
        tmprsa.cl_rsa_pub = request['data']['rsa_pub']
        tmpdf.my_pub = pow(tmpdf.pr_root, tmpdf.private, tmpdf.prime)
        tmpdf.shared_key = pow(tmpdf.cl_pub, tmpdf.private, tmpdf.prime)
        data = {
            "type": "secure",
            "payload": json.dumps({
                "type": "refresh",
                "data": {
                    "df_pr_root": tmpdf.pr_root,
                    "modulus_prime": tmpdf.prime,
                    "pub": tmpdf.my_pub,
                    "rsa_pub": tmprsa.my_rsa_pub
                }
            })
        }
        sender.send(data)
        sender.dfutils = tmpdf
        sender.RSAutils = tmprsa

    def processSecure(self, sender, request):
        """
        Process a secure message from a client
        """
        if sender.state != STATE_CONNECTED:
            logging.warning("SECURE from disconnected client: %s" % sender)
            return
        sa_data = request["sa_data"]
        del request["sa_data"]
        signed = request['signed']
        del request['signed']
        if not CC.verifySignature(sender.cert, json.dumps(request,sort_keys=True), base64.b64decode(signed)):
            print "unvalid signature client->server"
            return
        if not Utils.validate_HMAC(request,sender.agreedcipher, sa_data, sender.diffie_utils.shared_key):
            print "unvalid HMAC client->server"
            return
        request['payload'] = Utils.decipher(cipher=sender.agreedcipher, priv_sym=sender.RSAutils.my_rsa_priv,
                                            diffie_shared=sender.diffie_utils.shared_key, ciphered_json=request['payload'])

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return

        if 'type' not in request['payload'].keys():
            logging.warning("Secure message without inner frame type")
            return
        print colored(request["payload"],"red")
        if request["payload"]["ID"] != sender.last_received+1:
            logging.warning("Message out of order")
            return
        sender.last_received += 1
        if request['payload']['type'] == 'list':
            self.processList(sender, request['payload'])
            return

        if request['payload']['type'] == 'refresh':
            self.processRefresh(sender, request['payload'])
            return

        if not all(k in request['payload'].keys() for k in ("src", "dst")):
            return

        if not request['payload']['dst'] in self.id2client.keys():
            logging.warning("Message to unknown client: %s" % request['payload']['dst'])
            return
        if request['payload']['type'] == 'client-com':
            if self.id2client[request['payload']['src']].level > self.id2client[request['payload']['dst']].level:
                failed_ack = { "type" : "secure",
                        "payload": {
                            "type": "ack",
                            "topic": "failed_" + request['payload']['type'],
                            "data": {
                                        "dst" : request['payload']['dst']
                                    }
                                }
                        }
                dst = self.id2client[request['payload']['src']]
                dst.send(failed_ack)
                return
        dst = self.id2client[request['payload']['dst']]
        dst_message = {'type': 'secure', 'payload': request['payload']}
        dst.send(dst_message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', dest='port', default=8080, type=int)
    args = parser.parse_args()
    PORT = args.port
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                        formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    serv = None
    while True:
        try:
            logging.info("Starting Secure IM Server v1.0")
            serv = Server(HOST, PORT, False)
            serv.loop()
        except KeyboardInterrupt:
            serv.stop()
            try:
                logging.info("Press CTRL-C again within 2 sec to quit")
                time.sleep(2)
            except KeyboardInterrupt:
                logging.info("CTRL-C pressed twice: Quitting!")
                break
        except:
            logging.exception("Server ERROR")
            if serv is not (None):
                serv.stop()
            time.sleep(10)
