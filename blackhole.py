from gevent.server import StreamServer
from gevent import ssl
from gevent import socket
from datetime import datetime
import os
import time

global ttl
ttl = 60

#iptables -t nat -A PREROUTING -p tcp --dport 1:65535 -j REDIRECT --to-ports 5000

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

def recv(sock):
    buf = ""
    try:
        buf = sock.recv(1)
    except socket.timeout:
        buf = ""
    return buf

def handle(socket, address):
    global ttl
    socket.settimeout(ttl)
    ip, port = address
    buf = ""
    dport = 0
    try:
        dport = int(os.popen("grep \"src=%s\" /proc/net/nf_conntrack | grep \"sport=%d\"| tail -n 1" % (ip, port,)).read().split("dport=", 1)[1].split(" ", 1)[0])
    except:
        pass

    if dport == 0:
        try:
            dport = int(os.popen("grep \"src=%s\" /proc/net/ip_conntrack | grep \"sport=%d\"| tail -n 1" % (ip, port,)).read().split("dport=", 1)[1].split(" ", 1)[0])
        except:
            pass
    log = "[+] Connection on Port: %d from %s:%d Time: %s\n" % (dport, ip, port, datetime.utcnow().isoformat())
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
                        break
                    buf+=buffer
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
                    socket.close()
                else:
                    buf+= buffer
    except Exception as e:
        print "[-] Error : %s " % (e,)
    with open("captures/%d_%s_%d_%s.txt" % (dport, ip, port, datetime.utcnow().isoformat().replace(":", "-").replace(".", "-"),) , "wb") as file:
        file.write(buf)
        file.close()    

if not os.path.exists("captures"):
        os.makedirs("captures")
server = StreamServer(('', 5000), handle)
try:
    server.serve_forever()
except KeyboardInterrupt as e:
    pass
