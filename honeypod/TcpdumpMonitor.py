#!/usr/bin/python3
import subprocess
import os
import sys
import psutil
from socket import AF_INET

log_env_name = "HONEYPOD_LOG"
dnsserver_env_name="dnsServer"
dnsforwarder_env_name="dnsForwarder"
syslog_env_name="syslogServer"

if  log_env_name in os.environ:
    honeylog = os.getenv(log_env_name)
else:
    honeylog = '/var/log/honeypod'

if dnsserver_env_name in os.environ:
    dnsServer = os.getenv(dnsserver_env_name)
else:
    dnsServer = '1.1.1.1'

if dnsforwarder_env_name in os.environ:
    dnsServerForwarder = os.getenv(dnsserver_env_name)


    if syslog_env_name in os.environ:
    syslogServer = os.getenv(syslog_env_name)

#
# Get my interface; default eth0
#
network_interface = "eth0"
ip_address = ""


net_interfaces = psutil.net_if_addrs()

found = False
for interface, addresses in net_interfaces.items():
    for address in addresses:                                            
        if interface != "lo" and not address.address.startswith("127."): 
            network_interface = interface                                
            ip_address = address.address
            found = True
            break
    if found:
        break

class TcpdumpMonitor:
    def __init__(self, api_key):
        self.api_key = api_key

    def monitor_tcpdump(self, program_path, interface, traffic_filter, log_path):
         
        exec_array= [program_path, "-ni", interface, "-tttt", traffic_filter]
        process = subprocess.Popen(exec_array, stdout=subprocess.PIPE, 
                                   stderr=subprocess.STDOUT, universal_newlines=True)
        msg = ""
        res = ""
        parsed_data = []
        tmp =[]
        tmp2 =[]
        for line in process.stdout:
            print(line.strip())
            if ('>' in line) :
               #msg = line
               match = line.split()
               if match:
                   tmp = match[3].split('.')
                   tmp2= match[5].split('.')
                   source_port = tmp.pop(4)
                   source_ip = ".".join(tmp)
                   dest_port = tmp2.pop(4)
                   dest_ip = ".".join(tmp2)
                   tstamp = match[1]
                   today = match[0]
                   protocol = ""
                   parsed_data.append(f" Source IP: {source_ip},  "
                               f" Dest Port: {dest_port}, time: {today} {tstamp}")
                   msg = " ".join(parsed_data) 
                   print(msg)
                   command = \
                      'echo -{} "HONEYPOD: Suspicious network traffic:{}" >> {}\n'.format(
                          'e', msg, log_path)
                   os.system(command)
               else:
                parsed_data = []                   
            else:
             msg = ''

        process.wait()
        
        return process.returncode
  

# Example usage
def main():
    api_key = "<your-key>"
    monitor = TcpdumpMonitor(api_key)
    tcpdump_program_path = "/usr/bin/tcpdump"
    
    tcpfilter = f"not src host {ip_address} " \
                f"and not src host {dnsServer} " \
                f"and not src host {syslogServer} " \
                f"and not src host {dnsForwarder}"

    monitor.monitor_tcpdump(tcpdump_program_path, interface, 
                            tcpfilter, honeylog)

if __name__ == '__main__':
    main()

