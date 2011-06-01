#!/usr/bin/env python
# growth.py - Self-sustaining Python Network
#

"""
growth.py is the application that exists as one node in one large network
of little Python agents.

TODO: openssl keypair command here.
"""

from time import time
from uuid import uuid1 as uuid
import base64
import cPickle as pickle
import hashlib
import inspect
import logging
import marshal
import optparse
import os
import random
import select
import socket
import socket
import sys

try:
    import OpenSSL
    openssl_version = [int(p) for p in OpenSSL.version.__version__.split(".")]
    if openssl_version[0] <= 0 and openssl_version[1] < 12:
        raise ImportError, "invalid OpenSSL version, >=0.12 required"
    from OpenSSL import crypto
except ImportError, e:
    print >>sys.stderr, "error:", e
    print >>sys.stderr, "easy_install [-U] pyopenssl"
    sys.exit(1)



# Default values and globals:
opts = None
leader = "# signature:"

# network state stuff:
seen = []         # packets seen, TODO: limit this list, and dont make it global
mtu = 1400        # maximum packet size, used for reading from socket
lcc = 4           # desired number of neighbors/connections
timeout = 60.0    # general timeout before pingen




# command functions:

def cmd_listen():
    """usage: %prog [<opts>] listen [-f]"""
    return cmd_connect()

def cmd_connect( host=None, port=1848 ):
    global seen

    port = int(port)

    # load public certificate:
    with open( os.path.expanduser(opts.certfile) ) as fp:
        cert = crypto.load_certificate( crypto.FILETYPE_PEM, fp.read() )

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
        sock.sendto( packet( "helo" ), (host, port) )

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
            except (IndexError, ValueError, pickle.UnpicklingError), e:
                logging.warning( "illegal packet received: %s", e.args[0] )
                continue
            if packettype != "reply" and packetid is seen:
                continue
            logging.debug( "%s:%d sent %s_%s( %s )",
                    addr[0], addr[1], packettype, subject, repr(data)[:32] )

            if addr in network:
                network[addr] = now

            if packettype == "request":
                if subject == "ping":
                    sock.sendto( packet("pong", now, packetid), addr )

                elif subject == "helo":
                    if addr not in network:
                        if len(network) < lcc:
                            pkt = packet("welcome", set(network), packetid)
                            sock.sendto(pkt,addr)
                            network[addr] = now
                            logging.info( "received helo and accepted: %s:%d",
                                    addr[0], addr[1] )
                        else:
                            sock.sendto( packet("go away", set(network),
                                packetid), addr)
                            logging.debug( "received helo and refused" )

                elif subject == "rewire" and data in network:
                    sock.sendto(packet("kill", addr),data)
                    sock.sendto(packet("done", data, packetid), addr)
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
                    sock.sendto( packet("collect", copy, packetid), addr )

                elif subject == "python" and len(data)==2:
                    if data[0] not in seen:
                        seen.append( data[0] )
                        for n in network:
                            sock.sendto( packet("python", data), n )

                        pythoncode = data[1]
                        datahash = hashpython( pythoncode )

                        valid = False
                        for line in pythoncode.splitlines():
                            if not line.startswith( leader ):
                                continue
                            signature = line.lstrip( leader ).strip()
                            signature = base64.b64decode( signature )
                            try:
                                crypto.verify( cert, signature,
                                        datahash, "sha256" )
                                valid = True
                                break
                            except crypto.Error, e:
                                continue

                        if valid:
                            logging.info( "executing python code! %s", data[0] )
                            exec pythoncode
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
                            sock.sendto( packet("helo"), n )

                elif subject == "go away":
                    logging.info( "bounced on full node" )
                    unknown = data - set(network) # untrusted
                    n = random.choice( tuple(unknown) )
                    sock.sendto( packet("rewire", n), addr )
                    sock.sendto( packet("rewire", addr), n )
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
                                sock.sendto( packet("collect"), n )
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
                    sock.sendto( packet("ping",now), n )
                elif age > timeout * 1.3: # select factor is .25
                    logging.warning( "%s:%d declared MIA", n[0], n[1] )
                    sock.sendto( packet("kill"), n )
                    del network[n]


            # head count, comment todo
            if len(network) == 0 and host is not None: # I'm alone, connecting
                logging.info( "retrying to join %s:%s", host, port )
                sock.sendto( packet( "helo" ), (host, port) )
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
                    sock.sendto( packet("collect"), n )
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
                        sock.sendto( packet("helo"), n )
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
                        sock.sendto( packet("helo"), n )

                collection = None


def cmd_send( filename, host="::1", port=1848 ):
    """usage: todo"""

    s = socket.socket( socket.AF_INET6, socket.SOCK_DGRAM )
    with open( filename ) as fp:
        data = (uuid(), fp.read())
    s.sendto( packet("python", data), (host, port) )
    s.close()



def cmd_verify( filename ):
    """usage: %prog [<opts>] verify <filename>"""

    # load public certificate:
    with open( os.path.expanduser(opts.certfile) ) as fp:
        cert = crypto.load_certificate( crypto.FILETYPE_PEM, fp.read() )

    # load pythoncode data for matching:
    data = hashpythonfile( filename )

    # loop all lines and verify a found signature:
    found = False
    with open( filename ) as fp:
        for line in fp:
            if not line.startswith( leader ):
                continue
            signature = line.lstrip( leader ).strip()
            signature = base64.b64decode( signature )
            found = True
            try:
                crypto.verify( cert, signature, data, "sha256" )
            except crypto.Error:
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

def daemonize(redirect=os.devnull):
    """Fork this process in the background."""
    if os.fork() > 0:
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
            description=__doc__
        )
    parser.add_option( "-k", "--key", dest="keyfile", default="~/.growth.key",
            help="The private key vor signing python code", metavar="FILE" )
    parser.add_option( "-c","--cert", dest="certfile", default="~/.growth.crt",
            help="The certificate for verifing python code", metavar="FILE" )
    parser.add_option( "-f", "--nofork", dest="fork", default=True,
            action="store_false", help="Don't fork progress into background" )
    parser.add_option( "-l", "--listen", dest="listenport", default=1848,
            type="int", help="The port to listen on (cmd == listen)" )
    (opts, args) = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(1)

    try:
        cmd = args[0]
        func = globals()["cmd_"+cmd]
    except KeyError:
        print >>std.stderr, "error: no such command: " + cmd
        print >>std.stderr, "'{0} --help' for more info".format(prog)
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

    # TODO: Setup logging from config or cli
    logging.basicConfig( level=logging.DEBUG )

    try:
        func( *args[1:] )
    except KeyboardInterrupt:
        print "quit"

if __name__ == "__main__":
    main()

# vim: expandtab tabstop=4 softtabstop=4 shiftwidth=4 textwidth=79:
