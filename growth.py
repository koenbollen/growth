#!/usr/bin/env python
# growth.py - Self-sustaining Python Network
#             Koen Bollen <meneer koenbollen nl>
#             2011 GPL

"""
growth.py is the application that exists as one node in one large network
of little Python agents.

growth.py is the service and toolkit for creating a self-sustaining network
of Python nodes without a central server or a command&control-channel. This
is an IPv6-only project due to problems surrounding NAT, routing and firewalls,
also this was started as a demo for the IPv6Day in Holland.

With such a network, full of growth.py nodes, you able to create a python job
or python file, sign it with your private key (and let friends sign it with
theirs) and send it into the network. Every node will receive this python file,
but only the those who can verify it with a stored public certificate will
execute them. Now, this is were things gets interesting; You can create
distributed computing tasks, or launch a large DDOS attack. It's even possible
to create a self-updater job (code included). Every thing that the programming
language Python can do is now done distributed.


This application have the follow commands available:
 *   sign    - used to sign a Python file.
 *   verify  - will manually verify a Python file.
 *   connect - the main command to start a growth.py node, this command
               will start the Python service that joins the network.
               this service will manage connections with the network
               and it waits for incoming Python files to execute. When
               a file is received it is verified with the public certificates
               in memory loaded at startup.
 *   send    - this command can send a Python file into an existing
               network, only if the file is signed with a key matching
               a node's certificate will it be executed.

The following two openssl commands are an example to generate a private key
and a certificate:
# openssl genrsa [-des3] -out ~/.growth.key 2048
# openssl req -new -x509 -days 365 -key ~/.growth.key -out ~/.growth.crt

When verifying python code this application will check for certificates
at the following locations:
 *   /etc/growth.crt when root
 *   ~/.growth.crt
 *   ~/.growth/*.crt for multiple certificates
 *   This python file, add the certificate as non used string.
 *   the file specified using the command-line-interface (-c, --cert)
"""

from glob import glob
from time import time
from uuid import uuid1 as uuid
from StringIO import StringIO
import base64
import cPickle as pickle
import hashlib
import inspect
import logging
import logging.config
import marshal
import optparse
import os
import random
import select
import socket
import socket
import sys
import traceback

try:
    import OpenSSL
    openssl_version = [int(p) for p in OpenSSL.version.__version__.split(".")]
    if openssl_version[0] <= 0 and openssl_version[1] < 12:
        raise ImportError, "invalid OpenSSL version, >=0.12 required"
    from OpenSSL import crypto
except ImportError, e:
    print >>sys.stderr, "error:", e
    print >>sys.stderr, "easy_install -U pyopenssl"
    sys.exit(1)



# Default values and globals:
opts = None
leader = "# signature:"
thisAlgorithmBecomingSkynetCost = 999999999

# network state stuff:
seen = []         # packets seen, TODO: limit this list, and dont make it global
mtu = 24000       # maximum packet size, used for reading from socket
lcc = 4           # desired number of neighbors/connections
timeout = 300.0   # general timeout before pingen




# command functions:

def cmd_listen():
    """usage: %prog [<opts>] listen [-f] (alias for connect)"""
    return cmd_connect()

def cmd_connect( host=None, port=1848 ):
    global seen

    port = int(port)

    # load public certificates:
    certs = load_certificates()
    if len(certs) <= 0:
        print >>sys.stderr, "error: no certificates found"
        sys.exit(1)

    # go background:
    if opts.fork:
        daemonize()

    # create listen socket:
    try:
        sock = socket.socket( socket.AF_INET6, socket.SOCK_DGRAM )
        sock.bind( ('', opts.listenport) )
    except socket.error, e:
        print >>sys.stderr, "error:", e
        sys.exit(1)
    logging.info( "listening on %d", opts.listenport )

    # join growth.py network if specified:
    if host is not None:
        logging.info( "trying to join %s:%s", host, port )
        sendto(sock, packet( "helo" ), (host, port) )

    network = {}      # current connected network
    collection = None # used for collecting neighbor info

    selectime = 0
    while True:
        if selectime <= 0:
            selectime += timeout * 0.25
        pre = time()
        rfds, _, _ = select.select( [sock,], [], [], selectime )
        now = time()
        selectime -= now-pre

        if sock in rfds:
            try:
                raw, addr = sock.recvfrom( mtu, socket.MSG_DONTWAIT )
            except socket.error, e:
                logging.error( "unable to receive: %s", e.args[0] )
                continue

            try:
                packettype, packetid, subject, data = pickle.loads(raw)
            except (EOFError, IndexError, ValueError, pickle.UnpicklingError), e:
                logging.warning( "illegal packet received: %s", e )
                continue
            if packettype != "reply" and packetid is seen:
                continue
            logging.debug( "%s:%d sent %s_%s( %s )",
                    addr[0], addr[1], packettype, subject, repr(data)[:32] )

            if addr in network:
                network[addr] = now

            if packettype == "request":
                if subject == "ping":
                    sendto(sock, packet("pong", now, packetid), addr )

                elif subject == "helo":
                    if addr in network: # a reconnect
                        del network[addr]
                    if len(network) < lcc:
                        pkt = packet("welcome", set(network), packetid)
                        sendto(sock,pkt,addr)
                        network[addr] = now
                        logging.info( "received helo and accepted: %s:%d",
                                addr[0], addr[1] )
                    else:
                        sendto(sock, packet("go away", set(network),
                            packetid), addr)
                        logging.debug( "received helo and refused" )

                elif subject == "rewire" and data in network:
                    sendto(sock,packet("kill", addr),data)
                    sendto(sock,packet("done", data, packetid), addr)
                    del network[data]
                    network[addr] = now
                    logging.info( "rewired %s:%d -> %s:%d",
                            data[0], data[1], addr[0], addr[1] )

                elif subject == "kill":
                    if addr in network:
                        del network[addr]

                elif subject == "collect":
                    copy = set(network)
                    if addr in copy:
                        copy.remove(addr)
                    sendto(sock, packet("collect", copy, packetid), addr )

                elif subject == "python" and len(data)==2:
                    if data[0] not in seen:
                        seen.append( data[0] )
                        for n in network:
                            sendto(sock, packet("python", data), n )

                        pythoncode = data[1]
                        datahash = hashpython( pythoncode )

                        valid = False
                        for line in pythoncode.splitlines():
                            if not line.startswith( leader ):
                                continue
                            signature = line.lstrip( leader ).strip()
                            try:
                                signature = base64.b64decode( signature )
                            except TypeError, e:
                                logging.warning( "base64 error: %s", repr(e) )
                                continue
                            for cert in certs:
                                try:
                                    crypto.verify( cert, signature,
                                            datahash, "sha256" )
                                    valid = True
                                    break
                                except crypto.Error, e:
                                    continue
                            if valid:
                                break

                        if valid:
                            logging.info( "executing python code! %s", data[0] )
                            execute( pythoncode )
                        else:
                            logging.debug( "no valid hash found" )

                else:
                    logging.warning( "unknown request: %s( %s )",
                            subject, repr(data)[:32] )


            elif packettype == "reply":

                if subject == "pong":
                    pass

                elif subject == "welcome":
                    if len(network) == 0:
                        logging.info( "joined network!" )
                    network[addr] = now
                    for n in data: # untrusted
                        if n not in network:
                            sendto(sock, packet("helo"), n )

                elif subject == "go away":
                    logging.info( "bounced on full node" )
                    unknown = data - set(network) # untrusted
                    n = random.choice( tuple(unknown) )
                    sendto(sock, packet("rewire", n), addr )
                    sendto(sock, packet("rewire", addr), n )
                    selectime = 1

                elif subject == "done":
                    if len(network) == 0:
                        logging.info( "joined network!" )
                    network[addr] = now

                elif subject == "collect" and collection is not None:
                    # TODO: valid data, needs to be a set()
                    collection[addr] |= data
                    collection['received'] += 1
                    if addr in network: # this was first ply
                        for n in data:
                            if n not in collection:
                                collection['desired'] += 1
                                sendto(sock, packet("collect"), n )
                                collection[n] = set()
                    if collection['received'] == collection['desired']:
                        selectime = 1


        else: # timeout reached

            # ping round, send ping to neighbors who've been silent for
            # timeout seconds, and kill neighbors that didn't reply
            # in 1.3*timeout: (when value is negative a ping has been sent)
            for n in set(network):
                age = now - abs(network[n])
                if network[n] > 0 and age > timeout:
                    logging.info( "pinging %s:%d", n[0], n[1] )
                    network[n] *= -1
                    sendto(sock, packet("ping",now), n )
                elif age > timeout * 1.3: # select factor is .25
                    logging.warning( "%s:%d declared MIA", n[0], n[1] )
                    sendto(sock, packet("kill"), n )
                    del network[n]


            # head count, comment todo
            if len(network) == 0 and host is not None: # I'm alone, connecting
                logging.info( "retrying to join %s:%s", host, port )
                sendto(sock, packet( "helo" ), (host, port) )
            elif len(network) >= lcc: # complete
                collection = None
            elif 0 < len(network) < lcc and collection is None: # not enough
                logging.warning( "low lcc, collection neighbor information" )
                collection = {
                        'start': now,
                        'received': 0,
                        'desired': len(network)
                    }
                for n in network:
                    sendto(sock, packet("collect"), n )
                    collection[n] = set()
            elif collection is not None and (
                        collection['received'] == collection['desired'] or
                        collection['start'] < now-(timeout*0.5) # check value
                    ):
                #from pprint import pprint
                #pprint( collection )

                # clean collection data:
                for k in ("start", "received", "desired"):
                    del collection[k]

                found = False
                for n in collection:
                    if n not in network and len(collection[n]) < lcc:
                        # found not-neighbor with less then lcc!
                        sendto(sock, packet("helo"), n )
                        found = True
                        break

                # no slot found:
                if not found:

                    # building unknown nodeset:
                    unknown = set()
                    for n in collection:
                        unknown.add( n )
                        unknown |= collection[n]
                    unknown -= set(network)

                    if len(unknown) > 0:
                        n = random.choice( tuple(unknown) )
                        sendto(sock, packet("helo"), n )

                collection = None


def cmd_send( filename, host="::1", port=1848 ):
    """usage: %prog [<opts>] send <signed-file>"""

    s = socket.socket( socket.AF_INET6, socket.SOCK_DGRAM )
    with open( filename ) as fp:
        data = (uuid(), fp.read())
    s.sendto( packet("python", data), (host, port) )
    s.close()



def cmd_verify( filename ):
    """usage: %prog [<opts>] verify <filename>"""

    # load public certificates:
    certs = load_certificates()
    if len(certs) <= 0:
        print >>sys.stderr, "error: no certificates found"
        sys.exit(1)

    # load pythoncode data for matching:
    data = hashpythonfile( filename )

    # loop all lines and verify a found signature:
    found = False
    valid = False
    with open( filename ) as fp:
        for line in fp:
            if not line.startswith( leader ):
                continue
            found = True

            signature = line.lstrip( leader ).strip()
            signature = base64.b64decode( signature )
            for cert in certs:
                try:
                    crypto.verify( cert, signature, data, "sha256" )
                    valid = True
                    break
                except crypto.Error:
                    pass

            if not valid:
                continue

            print "signature ok"
            return

    if not found:
        print "no signature found in file"
    else:
        print "invalid signature"

def cmd_sign( filename ):
    """usage: %prog [<opts>] sign <filename>"""

    # load private key:
    with open( os.path.expanduser(opts.keyfile) ) as fp:
        key = crypto.load_privatekey( crypto.FILETYPE_PEM, fp.read() )

    # sign the pythoncode data and convert to base64:
    data = hashpythonfile( filename )
    signature = crypto.sign( key, data, "sha256" )
    result = base64.b64encode( signature )

    # check of signature isn't already present:
    with open( filename ) as fp:
        for line in fp:
            if result in line:
                return

    # write signature to source as comment:
    with open( filename, "a" ) as fp:
        fp.write( "{0} {1}\n".format( leader, result ) )




# util functions:

def execute( pythoncode ):
    try:
        exec pythoncode
    except SystemExit:
        pass
    except Exception, e:
        logging.error( "exception while executing: %s", repr(e) )
        f = StringIO()
        traceback.print_exc(file=f)
        logging.debug( "traceback:\n" + f.getvalue().strip() )



def hashpythonfile( filename ):
    """Compile a python file and hash the code object."""
    with open(filename) as fp:
        return hashpython( fp.read() )

def hashpython( source ):
    """Compile python source and hash the code object."""
    code = compile( source, "<string>", "exec" )
    return hashlib.sha256( marshal.dumps( code ) ).hexdigest() # cant have \x00 in data

def packet( subject, data=None, packetid=None ):
    """Build a packet for sending over the growth.py network."""
    global seen
    packettype = "request" if packetid is None else "reply"
    if not packetid:
        packetid = str(uuid())
        seen.append( packetid )
    return pickle.dumps( (packettype, packetid, subject, data), -1 )

def sendto(sock, data, address ):
    """Wrapper for socket.socket.sendto(string[, flags], address)"""
    try:
        return sock.sendto( data, address )
    except (socket.error, IOError), e:
        logging.error( "error while sending: %s", e )
        return -1

def load_certificates():
    """Load all certificates that can be found."""
    files = [os.path.expanduser(opts.certfile),sys.argv[0]]
    files.extend(glob(os.path.join(os.path.expanduser("~/.growth"),"*.crt")))
    if os.getuid() == 0:
        files.append( "/etc/growth.crt" )
        files.extend(glob(os.path.join(os.path.expanduser("/etc/growth"),"*.crt")))
    #print files
    result = set()
    for filename in files:
        try:
            with open( filename, "rb" ) as fp:
                cert = crypto.load_certificate( crypto.FILETYPE_PEM, fp.read() )
                result.add( cert )
        except Exception, e:
            #print filename, e
            pass
    #print result
    logging.debug( "found %d certificates", len(result) )
    return tuple( result )

def daemonize(redirect=os.devnull, dontkill=False):
    """Fork this process in the background."""
    if os.fork() > 0:
        if dontkill:
            return
        os._exit(0)
    os.setsid()
    os.chdir("/")
    os.umask(0)
    if os.fork() > 0:
        os._exit(0)
    for i in xrange(1024):
        try:
            os.close(i)
        except OSError:
            pass
    os.open(redirect,os.O_RDWR|os.O_CREAT)
    os.dup2(0,1)
    os.dup2(0,2)
    return os.getpid()




# entry point:

def main():
    global opts
    prog = os.path.basename(sys.argv[0])
    parser = optparse.OptionParser(
            usage="%prog [<opts>] <cmd> <args...>",
            description=__doc__.split("\n\n")[0] # first paragraph.
        )
    parser.add_option( "--long-help", dest="longhelp", default=False,
            action="store_true", help="display a long help text and exit." )
    parser.add_option( "-k", "--key", dest="keyfile", default="~/.growth.key",
            help="the private key vor signing python code", metavar="FILE" )
    parser.add_option( "-c","--cert", dest="certfile", default="~/.growth.crt",
            help="certificate for verifing python code", metavar="FILE" )
    parser.add_option( "-f", "--nofork", dest="fork", default=True,
            action="store_false", help="don't fork progress into background" )
    parser.add_option( "-l", "--listen", dest="listenport", default=1848,
            type="int", help="the port to listen on (cmd == listen)" )
    parser.add_option( "-d", "--debug", dest="debug", default=False,
            action="store_true", help="so debugging information, implies -f" )
    parser.add_option( "-L", "--logconfig", dest="logconfig", default=None,
            help="load logging configuration from this file, see "
            +"http://docs.python.org/library/logging.config.html",
            metavar="FILE" )
    (opts, args) = parser.parse_args()

    if opts.longhelp:
        print __doc__
        sys.exit(0)

    if len(args) < 1:
        parser.print_help()
        sys.exit(1)

    if opts.debug:
        opts.fork = False
        logging.basicConfig(
                format="%(levelname)s: %(message)s",
                level=logging.DEBUG )
    elif opts.logconfig is not None:
        logging.config.fileConfig( opts.logconfig )

    try:
        cmd = args[0]
        func = globals()["cmd_"+cmd]
    except KeyError:
        print >>sys.stderr, "error: no such command: " + cmd
        print >>sys.stderr, "'{0} --help' for more info".format(prog)
        sys.exit(1)

    argspec = inspect.getargspec( func )
    argc = len(argspec.args)
    defs = argspec.defaults
    if defs is None:
        defs = []
    maxargc = len(argspec.args)
    minargc = maxargc-len(defs)
    if len(args)-1 < minargc or len(args)-1 > maxargc:
        print >>sys.stderr, func.__doc__.replace( "%prog", prog )
        sys.exit(1)
    if len(args)>1 and args[1] in ("-h", "--help"):
        print >>sys.stderr, func.__doc__.replace( "%prog", prog )
        sys.exit(0)

    try:
        func( *args[1:] )
    except KeyboardInterrupt:
        print "quit"

if __name__ == "__main__":
    main()

# vim: expandtab tabstop=4 softtabstop=4 shiftwidth=4 textwidth=79:
