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
import time
import logging
from security import *
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from termcolor import colored
from Crypto.Random import random
from Crypto.Hash import HMAC

# Server address
HOST = ""  # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2


class DiffieHellmanUtils:
    # sv diffie hellman
    private = random.randint(0, 256)
    mypub = -1
    prime = -1
    pr_root = -1
    cl_pub = -1
    shared = -1


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
        self.id = None
        self.sa_data = None
        self.level = 0
        self.state = STATE_NONE
        self.name = "Unknown"
        self.agreedcipher = None
        self.tmpdf = None
        self.tmprsa = None
        self.dfutils = DiffieHellmanUtils()
        self.RSAutils = RSAUtils()

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s name:%s level:%d state:%d)" % (
            self.id, str(self.addr), self.name, self.level, self.state)

    def asDict(self):
        # CHANGED
        # return {'id': self.id, 'level': self.level}
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
        """Send an object to this client.
        """
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
                self.processConnect(client, req)

            elif req['type'] == 'secure':
                self.processSecure(client, req)

        except Exception, e:
            logging.exception("Could not handle request")

    def clientList(self):
        """
        Return the client list
        """
        cl = []
        for k in self.clients:
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
                sender.send(msg)
                return
            elif request['phase'] == 3:
                sender.dfutils.prime = request["data"]["modulus_prime"]
                sender.dfutils.pr_root = request["data"]["df_pr_root"]
                sender.dfutils.cl_pub = request["data"]["pub"]
                sender.dfutils.mypub = pow(sender.dfutils.pr_root, sender.dfutils.private, sender.dfutils.prime)
                sender.dfutils.shared = pow(sender.dfutils.cl_pub, sender.dfutils.private, sender.dfutils.prime)
                msg['data']['pub'] = sender.dfutils.mypub
                msg['data']['df_pr_root'] = request["data"]["df_pr_root"]
                msg['data']['modulus_prime'] = request["data"]["modulus_prime"]
                sender.send(msg)
                return
            elif request['phase'] == 5:
                salt = request['data']['salt']
                hashed = pyscrypt.hash(password=str(sender.dfutils.shared),
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
                hashed = pyscrypt.hash(password=str(sender.dfutils.shared),
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
        sender.send(msg)
        sender.id = request['id']
        sender.agreedcipher = request['ciphers'][0]
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

        ackpayload = json.dumps({'type': 'ack', 'acktype': "list"})
        ackpayload = Utils.cipher(cipher=sender.agreedcipher, pub_sym=sender.RSAutils.cl_rsa_pub,
                                  diffie_shared=sender.dfutils.shared, message=ackpayload)

        sender.send({'type': 'secure',
                     'payload': ackpayload,
                     })
        payload = json.dumps({'type': 'list', 'data': self.clientList()})

        payload = Utils.cipher(cipher=sender.agreedcipher, pub_sym=sender.RSAutils.cl_rsa_pub,
                               diffie_shared=sender.dfutils.shared, message=payload)
        msg = {'type': 'secure', 'payload': payload}
        sender.send(msg)

    def processRefresh(self, sender, request):
        tmpdf = DiffieHellmanUtils()
        tmprsa = RSAUtils()
        tmpdf.cl_pub = request['data']['pub']
        tmpdf.pr_root = request['data']['df_pr_root']
        tmpdf.prime = request['data']['modulus_prime']
        tmprsa.cl_rsa_pub = request['data']['rsa_pub']
        tmpdf.mypub = pow(tmpdf.pr_root, tmpdf.private, tmpdf.prime)
        tmpdf.shared = pow(tmpdf.cl_pub, tmpdf.private, tmpdf.prime)
        data = {
            "type": "secure",
            "payload": json.dumps({
                "type": "refresh",
                "data": {
                    "df_pr_root": tmpdf.pr_root,
                    "modulus_prime": tmpdf.prime,
                    "pub": tmpdf.mypub,
                    "rsa_pub": tmprsa.my_rsa_pub
                }
            })
        }
        data['payload'] = Utils.cipher(cipher=sender.agreedcipher, pub_sym=sender.RSAutils.cl_rsa_pub,
                                       diffie_shared=sender.dfutils.shared, message=data['payload'])
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
        request['payload'] = Utils.decipher(cipher=sender.agreedcipher, priv_sym=sender.RSAutils.my_rsa_priv,
                                            diffie_shared=sender.dfutils.shared, ciphered_json=request['payload'])
        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return
        if 'type' not in request['payload'].keys():
            logging.warning("Secure message without inner frame type")
            return

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

        dst = self.id2client[request['payload']['dst']]

        payload = Utils.cipher(cipher=dst.agreedcipher, pub_sym=dst.RSAutils.cl_rsa_pub,
                               diffie_shared=dst.dfutils.shared, message=json.dumps(request['payload']))

        dst_message = {'type': 'secure', 'payload': payload}
        dst.send(dst_message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', dest='port', default=8080, type=int)
    parser.add_argument('-d', '--debug', dest='debug', action='store_true')
    args = parser.parse_args()
    PORT = args.port
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                        formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    serv = None
    while True:
        try:
            logging.info("Starting Secure IM Server v1.0")
            serv = Server(HOST, PORT, args.debug)
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
