from gevent.server import StreamServer
from gevent import ssl
from gevent import socket
from datetime import datetime
from gevent.server import DatagramServer
import gevent
import os
import time

global ttl, httpData
ttl = 10
httpData = "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nContent-Length: 0\n\n"

#iptables -t nat -A PREROUTING -p tcp --dport 1:65535 -j REDIRECT --to-ports 5000
#iptables -t nat -A PREROUTING -p udp --dport 1:65535 -j REDIRECT --to-ports 5000

def telnetparse(input):
    if "echo" in input and "-e" in input:
        for ino in input.split(" "):
            if '"' in ino:
                if "\\x" in ino:
                    ino = ino.replace('"','').replace("\\x", "").replace("\r", "").replace("\n","")
                    return ino.decode("hex")
            elif "'" in ino:        
                if "\\x" in ino:
                    ino =  ino.replace("'",'').replace("\\x", "").replace("\r", "").replace("\n","")
                    return ino.decode("hex")
            elif "\\\\x" in ino:
                ino =  ino.replace("\\\\x", "").replace("\r", "").replace("\n","")
                return ino.decode("hex")

    elif "echo " == input[:5]:
        toout = input[5:]
        if '"' in toout:
            ino = ino.replace('"','').replace("\r", "").replace("\n","")
        elif "'" in toout:
            ino =  ino.replace("'",'').replace("\r", "").replace("\n","")
        else:
            ino = toout
        return ino
    return None    

def checkHTTP(input):
    if "HTTP/" in input and ( input[-4:] == "\r\n\r\n"  or input[-2:] == "\n\n" ):
        return True
    return False

def recv(sock):
    buf = ""
    try:
        buf = sock.recv(1)
    except socket.timeout:
        buf = ""
    return buf

def handleTCP(socket, address):
    global ttl, httpData
    socket.settimeout(ttl)
    httpFlag = False
    ip, port = address
    buf = ""
    dport = 0
    try:
        dport = int(os.popen("grep \"src=%s\" /proc/net/nf_conntrack | grep tcp | grep \"sport=%d\"| tail -n 1" % (ip, port,)).read().split("dport=", 1)[1].split(" ", 1)[0])
    except:
        pass

    if dport == 0:
        try:
            dport = int(os.popen("grep \"src=%s\" /proc/net/ip_conntrack | grep tcp | grep \"sport=%d\"| tail -n 1" % (ip, port,)).read().split("dport=", 1)[1].split(" ", 1)[0])
        except:
            pass
    log = "[+] TCP Connection on Port: %d from %s:%d Time: %s\n" % (dport, ip, port, datetime.utcnow().isoformat())
    print log,
    with open("logs.txt", "a") as f:
        f.write(log)
        f.close()
    try:
        if dport in [443] or 443 == dport%1000:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile="ssl.crt", keyfile="ssl.key")
            context.options = ssl.OP_ALL
            try:
                sslsock = context.wrap_socket(socket, server_side=True)
                while True:
                    buffer = sslsock.read()
                    if not buffer:
                        sslsock.send(httpData)
                        break
                    buf+=buffer
                    if checkHTTP(buf):
                        httpFlag = True

            except Exception as e:
                print "[-] Error: %s" % (e,)
            finally:
                    try:
                        sslsock.close()
                    except:
                        pass
        elif dport in [23]:
            socket.send("login: ")
            while  not socket.closed:
                buffer = recv(socket)
                if not buffer:
                    socket.close()
                    break
                elif buffer == "\n":
                    buf+= buffer
                    break
                else:
                    buf+=buffer
            if not socket.closed:
                socket.send("Password: ")
            while  not socket.closed:
                buffer = recv(socket)
                if not buffer:
                    socket.close()
                    break
                elif buffer == "\n":
                    buf+= buffer
                    socket.send("XM# ")
                    break
                else:
                    buf+=buffer
            while not socket.closed:
                
                buffer = recv(socket)
                if not buffer:
                    socket.close()
                    break
                elif buffer == "\n":
                    tosend = telnetparse(buf.split("\n")[-1])
                    if tosend <> None:
                        socket.send(tosend)
                        socket.send("\n")
                    buf+= buffer
                    socket.send("XM# ")
                else:
                    buf+= buffer 
                
                   

        else:
            while not socket.closed:
                buffer = recv(socket)
                if not buffer:
                    if httpFlag:
                        socket.send(httpData)
                    socket.close()
                    break
                else:
                    buf+= buffer
                    if checkHTTP(buf):
                        httpFlag = True
       
    except Exception as e:
        print "[-] Error : %s " % (e,)
    with open("captures/tcp/%d_%s_%d_%s.txt" % (dport, ip, port, datetime.utcnow().isoformat().replace(":", "-").replace(".", "-"),) , "wb") as file:
        file.write(buf)
        file.close()    

class UDPServer(DatagramServer):

    def handle(self, data, address):
        global ttl
        self.socket.settimeout(ttl)
        ip, port = address
        dport = 0
        try:
            dport = int(os.popen("grep \"src=%s\" /proc/net/nf_conntrack | grep udp | grep \"sport=%d\"| tail -n 1" % (ip, port,)).read().split("dport=", 1)[1].split(" ", 1)[0])
        except:
            pass

        if dport == 0:
            try:
                dport = int(os.popen("grep \"src=%s\" /proc/net/ip_conntrack | grep udp | grep \"sport=%d\"| tail -n 1" % (ip, port,)).read().split("dport=", 1)[1].split(" ", 1)[0])
            except:
                pass

        log = "[+] UDP Connection on Port: %d from %s:%d Time: %s\n" % (dport, ip, port, datetime.utcnow().isoformat())
        self.socket.close()
        print log,
        with open("logs.txt", "a") as f:
            f.write(log)
            f.close()
        with open("captures/udp/%d_%s_%d_%s.txt" % (dport, ip, port, datetime.utcnow().isoformat().replace(":", "-").replace(".", "-"),) , "wb") as file:
            file.write(data)
            file.close()    

if not os.path.exists("captures"):
        os.makedirs("captures")
if not os.path.exists("captures/tcp"):
        os.makedirs("captures/tcp")
if not os.path.exists("captures/udp"):
        os.makedirs("captures/udp")

tcpserver = StreamServer(('', 5000), handleTCP)
udpserver = UDPServer(('', 5000))

try:
    gevent.joinall( [gevent.spawn(tcpserver.serve_forever, () ), gevent.spawn(udpserver.serve_forever,() )] )
except KeyboardInterrupt as e:
    pass
