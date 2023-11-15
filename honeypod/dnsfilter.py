import os #AddedForHoneyPod
import psutil
from socket import AF_INET

'''
dns_filter.py: Copyright (C) 2014 Oliver Hitz <oliver@net-track.ch>

DNS filtering extension for the unbound DNS resolver. At start, it reads the
two files /etc/unbound/blacklist and /etc/unbound/whitelist, which contain a
host name on every line.

For every query sent to unbound, the extension checks if the name is in the
whitelist or in the blacklist. If it is in the whitelist, processing continues
as usual (i.e. unbound will resolve it). If it is in the blacklist, unbound
stops resolution and returns the IP address configured in intercept_address.

The whitelist and blacklist matching is done with every domain part of the
requested name. So, if www.domain.com is requested, the extension checks
whether www.domain.com, domain.com or .com is listed. 

Install and configure:

- copy dns_filter.py to /etc/unbound/dns_filter.py

- if needed, change intercept_address

- change unbound.conf as follows:

  server:
    module-config: "python validator iterator"
  python:
    python-script: "/etc/unbound/dns_filter.py"

- create /etc/unbound/blacklist and /etc/unbound/whitelist as you desire

- restart unbound

'''

#   GLOBALS
# 
#  Env var for set of whitelisted hosts ; initialize list to null
wl_env_name = "HONEYPOD_WHITELIST"
whitelist = set()

#  Env var for logfile; default value.
log_env_name = "HONEYPOD_LOG"
honeylog = '/var/log/honeypod'

#
# Get my interface; fail safe to 127.0.0.1 if we fail
#
intercept_address = "127.0.0.1"


net_interfaces = psutil.net_if_addrs()

for interface, addresses in net_interfaces.items():
    for address in addresses:
        if address.family == AF_INET and not address.address.startswith("127."):
             intercept_address = address.address

def check_name(name, xlist):
    while True:
        os.system(f'echo "xlist {str(xlist)}\n"')

        if (name in xlist):
            os.system(f'echo "FOUND IN LIST {str(name)}\n"')
            return True
        else:
            os.system(f'echo "NOT FOUND IN LIST {str(name)}\n"')
            return False;

def read_list(xlist):
     global wl_env_name
     white_list_spec = os.getenv(wl_env_name)
     os.system(f'echo "white_list_spec {white_list_spec}\n"')
     if white_list_spec is not None:
         white_list_array = white_list_spec.split(',')
         os.system(f'echo "white_list_array {str(white_list_array)}\n"')
         for item in white_list_array:
             whitelist.add(item)
         os.system(f'echo "xlist after split {str(xlist)}\n"')

def init(id, cfg):
    global honeylog
    global whitelist
    os.system(f'echo "intercept:  {intercept_address}\n"')

     
    log_info("dns_filter.py: ")
    read_list(whitelist)
    os.system(f'echo "whitelist returned from read_list {str(whitelist)}\n"')

    if log_env_name in os.environ:
        honeylog = os.getenv(log_env_name)
    return True

def deinit(id):
    return True

def inform_super(id, qstate, superqstate, qdata):
    return True

def operate(id, event, qstate, qdata):
    global whitelist
    if (event == MODULE_EVENT_NEW):
        os.system(f'echo "MODULE_EVENT_NEW\n"')
    
    if (event == MODULE_EVENT_PASS):
        os.system(f'echo "MODULE_EVENT_PASS\n"')

    if (event == MODULE_EVENT_REPLY):
        os.system(f'echo "MODULE_EVENT_REPLY\n"')

    if (event == MODULE_EVENT_NOREPLY):
        os.system(f'echo "MODULE_EVENT_NOREPLY\n"')

    if (event == MODULE_EVENT_MODDONE):
        os.system(f'echo "MODULE_EVENT_MODDONE\n"')

    if (event == MODULE_EVENT_ERROR):
        os.system(f'echo "MODULE_EVENT_ERROR\n"')

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):

        # Check if whitelisted.
        name = qstate.qinfo.qname_str.rstrip('.')
        os.system(f'echo "About to check name {name}\n"')

        if (check_name(name, whitelist)):
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            return True

#        if (check_name(name, blacklist)):    #AddedForHoneyPod treat blacklist/nonwhitelist the same.
        else:   #AddedForHoneyPod
#            log_info("dns_filter.py: "+name+" blacklisted")
            os.system(f'echo "HONEYPOD: Suspicious hostname request {name}" >> {honeylog}')
            log_info("HONEYPOD: Suspicious hostname resolution! %s" % name)
            msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
            if (qstate.qinfo.qtype == RR_TYPE_A) or (qstate.qinfo.qtype == RR_TYPE_ANY):
                msg.answer.append("%s 10 IN A %s" % (qstate.qinfo.qname_str, intercept_address))
            else:
                os.system(f'echo "intercept_address NOT returned from query\n"')

            if not msg.set_return_msg(qstate):
                os.system(f'echo "about to return MODULE_ERROR\n"')
                qstate.ext_state[id] = MODULE_ERROR 
                return True

            qstate.return_msg.rep.security = 2

            qstate.return_rcode = RCODE_NOERROR
            qstate.ext_state[id] = MODULE_FINISHED 
            return True
#        else:                              #AddedForHoneyPod blacklist/nonwhitelist same.
#            qstate.ext_state[id] = MODULE_WAIT_MODULE 
#            return True

    if event == MODULE_EVENT_MODDONE:
#        log_info("pythonmod: iterator module done")
        qstate.ext_state[id] = MODULE_FINISHED 
        return True
      
    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
