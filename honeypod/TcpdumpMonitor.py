import subprocess
import os


class TcpdumpMonitor:
    def __init__(self, api_key):
        self.api_key = api_key

    def monitor_tcpdump(self, program_path,interface, trafic_filter, log_path):
         
        exec_array= [program_path, "-ni", interface, "-tttt", trafic_filter]
        process = subprocess.Popen(exec_array, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        msg = ""
        res = ""
        parsed_data = []
        tmp =[]
        tmp2 =[]
        for line in  process.stdout:
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
                   parsed_data.append(f"HONEYPOD: Suspicious network traffic: Source IP: {source_ip},  "
                               f" Dest Port: {dest_port}, time: {today} {tstamp}")
                   msg = " ".join(parsed_data) 
                   print(msg)
                   command = 'echo -{} "{}" >> {}\n'.format('e', msg, log_path)
                   os.system(command)
               else:
                parsed_data = []                   
            else:
             msg = ''

        process.wait()
        
        return process.returncode

    def send_question(self, question, path_of_log):
        openai.api_key = self.api_key
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[

                {"role": "user", "content": question}
            ]
        )

        answer = response.choices[0].message.content
        print(f"Assistant: {answer}")
        command = 'echo "{}" >> {}'.format(answer, path_of_log)
        os.system(command) 
        
  

# Example usage
def main():
    api_key = "<your-key>"
    monitor = TcpdumpMonitor(api_key)
    tcpdump_program_path = "/usr/bin/tcpdump"
    log_path = "/var/log/honeypod.log"
    interface = "eth0"
    tcpfilter = f"not src host 172.17.0.2"
    monitor.monitor_tcpdump(tcpdump_program_path, interface, tcpfilter ,log_path)

if __name__ == '__main__':
    main()

