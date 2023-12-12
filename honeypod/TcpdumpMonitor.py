#!/usr/bin/python3
import subprocess
import os
import sys
import psutil
from socket import AF_INET


if "honeylog" in os.environ:
    honeylog = os.getenv(log_env_name)
else:
    honeylog = '/var/log/honeypod'

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

    def monitor_tcpdump(self, program_path,interface0, trafic_filter, log_path, awk_path):
         
        awk_command =  f" awk -f {awk_path} -v myip_arg={ip_address}"       
        #exec_array= [program_path, "-ni", interface, "-tttt", trafic_filter]
       
        tcp_command = f"{program_path}  -ni {interface0} -tttt {trafic_filter} "
        combined_command = f"{tcp_command} | {awk_command}"
        
        process = subprocess.Popen(combined_command,shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        msg = ""
        parsed_data = []
        
        for line in  process.stdout:
            print(line.strip())
            if ('.' in line) :
               msg = line
            
               command = 'echo -{} "HONEYPOD: Suspicious network traffic:{}" >> {}\n'.format('e', msg, log_path)
               #print(command)
               os.system(command)
                                  
            else:
             msg = ''

        process.wait()
        
        return process.returncode
  

# Example usage
def main():
    api_key = "<your-key>"
    monitor = TcpdumpMonitor(api_key)
    tcpdump_program_path = "/usr/bin/tcpdump"
    #tcpdump_program_path = "tcpdump"
    awk_file = "./pullIPAddresses.awk"
    #net_interfaces ="ens33"
        
    tcpfilter = f"not src host {ip_address}" 
    monitor.monitor_tcpdump(tcpdump_program_path, net_interfaces, tcpfilter, honeylog, awk_file)

if __name__ == '__main__':
    main()
