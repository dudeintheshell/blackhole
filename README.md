# Blackhole

Blackhole is a low-interactive Honeypot that captures and logs everything. Using iptables all incoming TCP and UDP request are redirected to a single port, hence it seems as if the Honeypot is listening on all ports. Telnet(23) and HTTPS ([0-65]443) requests are supported in a limited way. The Honeypot was written as a PoC to capture all requests and so, has limited features. 

Blackhole is not an ideal Honeypot, but is very useful for capturing IPs and Raw requests of automated scanners.

## Minimum requirements:

Debian with Python 2.7.9 and gevent package.

## Setup:


    git clone https://github.com/dudeintheshell/blackhole.git
    cd blackhole
    sudo apt-get install python-virtualenv python-setuptools python-dev build-essential
    virtualenv env
    source env/bin/activate
    pip install gevent


## Create SSL certificate :
(http://blog.justin.kelly.org.au/how-to-create-a-self-sign-ssl-cert-with-no-pa/)

This is required to support HTTPS request.

Generate key with openssl

    openssl genrsa -out ssl.key 1024

Create ‘Certificate Signing Request’ - and leave the passwords blank

    openssl req -new -key ssl.key -out ssl.csr

Create SSL certificate

    openssl x509 -req -days 366 -in ssl.csr -signkey ssl.key -out ssl.crt

## Setup iptables rule

If you want to redirect all TCP and UDP traffic to Blackhole use the following command:

    sudo iptables -t nat -A PREROUTING -p tcp --dport 1:65535 -j REDIRECT --to-ports 5000
    sudo iptables -t nat -A PREROUTING -p udp --dport 1:65535 -j REDIRECT --to-ports 5000

Suppose you have other services running on the Host e.g. 22, 445 and you don't want to capture them via Blackhole,you can create multiple iptables rules:

    sudo iptables -t nat -A PREROUTING -p tcp --dport 1:21 -j REDIRECT --to-ports 5000
    sudo iptables -t nat -A PREROUTING -p tcp --dport 23:444 -j REDIRECT --to-ports 5000
    sudo iptables -t nat -A PREROUTING -p tcp --dport 446:65535 -j REDIRECT --to-ports 5000


## Making nf_conntrack readable:

Since Blackhole listens on port 5000, its is hard to tell which port got the original request. Using nf\_conntrack/ip\_conntrack we can identify the actual port to which the connection was requested. If the Blackhole runs with lower privileges, we need to make nf\_conntrack readable for others:

    chmod +r /proc/net/nf_conntrack

OR

    chmod +r /proc/net/ip_conntrack


## Running Blackhole

Once everything is ready, go to the Blackhole's directory and execute the following commands:

    source env/bin/activate
    python blackhole.py


All captured data and binaries are stored in "captures" directory. Logs are stored in the "logs.txt" file.
