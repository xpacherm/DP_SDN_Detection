import sys
import subprocess
import signal
import os
import statistics
from datetime import datetime

command = "cd /home/marek/ryu && python3 ./bin/ryu-manager /home/marek/monitor.py"
flows = {}
MINUTES = 2 #Training data collecting length
TIMEOUT = 60 * MINUTES

class Flow:
    def __init__(self, time_start, datapath, inport, ethsrc, ethdst, l4proto, l4src, l4dst, outport, packets, bytes, psh, urg):
        self.time_start = time_start
        self.datapath = datapath
        self.inport = inport
        self.ethsrc = ethsrc
        self.ethdst = ethdst
        self.l4proto = l4proto
        self.l4src = l4src
        self.l4dst = l4dst
        self.outport = outport
        
        self.forward_packets = packets
        self.forward_bytes = bytes
        self.forward_packets_delta = 0
        self.forward_packets_delta_list = []
        self.forward_packets_IAT_list = [0]
        self.forward_bytes_delta = 0
        
        self.forward_psh_flags = psh
        self.forward_urg_flags = urg
        
        self.forward_status = 1
        self.forward_last_time = time_start
        
        self.backward_packets = 0
        self.backward_bytes = 0
        self.backward_packets_delta = 0
        self.backward_packets_delta_list = []
        self.backward_packets_IAT_list = [0]
        self.backward_bytes_delta = 0
        
        self.backward_psh_flags = 0
        self.backward_urg_flags = 0
        
        self.backward_status = 0
        self.backward_last_time = time_start
        
    """
    def process_delta_list(self, delta_list, IAR_list):
        if (len(delta_list) >= 2):
            if (delta_list[-1] != 0):
                for i in range(len(delta_list)-2, -1, -1):
                    if (delta_list[i] != 0):
                        break
                if (i < 0):
                    return
                zeroes_found = len(delta_list) - i - 2
                if (zeroes_found):
                    IAR_list.append(zeroes_found)
                for j in range(delta_list[-1]):
                    IAR_list.append(1/(delta_list[-1]))
                    """
    def update_forward(self, packets, bytes, psh, urg, current_time):
        self.forward_packets_delta_list.append(self.forward_packets_delta)
        self.forward_packets_delta = packets - self.forward_packets
        
        if (len(self.forward_packets_delta_list) >= 2):
            if (self.forward_packets_delta_list[-1] != 0):
                for i in range(len(self.forward_packets_delta_list)-2, -1, -1):
                    if (self.forward_packets_delta_list[i] != 0):
                        break
                zeroes_found = len(self.forward_packets_delta_list) - i - 2
                if (zeroes_found != 0 and i):
                    self.forward_packets_IAT_list.append(zeroes_found)
                for j in range(self.forward_packets_delta_list[-1] - 1):
                    self.forward_packets_IAT_list.append(1/(self.forward_packets_delta_list[-1]))
        
        self.forward_packets = packets
        
        self.forward_bytes_delta = bytes - self.forward_bytes
        self.forward_bytes = bytes
        
        self.forward_last_time = current_time
        
        self.forward_psh_flags = psh
        self.forward_urg_flags = urg
        
        if (self.forward_packets_delta == 0 or self.forward_bytes_delta == 0):
            self.forward_status = 0
        else:
            self.forward_status = 1
    
    def update_backward(self, packets, bytes, psh, urg, current_time):
        self.backward_packets_delta = packets - self.backward_packets
        self.backward_packets_delta_list.append(self.backward_packets_delta)
        
        if (len(self.backward_packets_delta_list) >= 2):
            if (self.backward_packets_delta_list[-1] != 0):
                for i in range(len(self.backward_packets_delta_list)-2, -1, -1):
                    if (self.backward_packets_delta_list[i] != 0):
                        break
                zeroes_found = len(self.backward_packets_delta_list) - i - 2
                if (zeroes_found != 0 and i):
                    self.backward_packets_IAT_list.append(zeroes_found)
                for j in range(self.backward_packets_delta_list[-1] - 1):
                    self.backward_packets_IAT_list.append(1/(self.backward_packets_delta_list[-1]))
        
        self.backward_packets = packets
        
        self.backward_bytes_delta = bytes - self.backward_bytes
        self.backward_bytes = bytes
        
        self.backward_last_time = current_time
        
        self.backward_psh_flags = psh
        self.backward_urg_flags = urg
        
        if (self.backward_packets_delta == 0 or self.backward_bytes_delta == 0):
            self.backward_status = 0
        else:
            self.backward_status = 1
            
def printflows(f, time):
    for key,flow in flows.items():
        avg_pkt_size = 0
        avg_fwd_size = 0
        avg_bwd_size = 0
        if (flow.forward_packets > 0):
            avg_fwd_size = (flow.forward_bytes / flow.forward_packets)
        if (flow.backward_packets > 0):
            avg_bwd_size = (flow.backward_bytes / flow.backward_packets) 
        if (flow.forward_packets > 0 or flow.backward_packets > 0):
            avg_pkt_size = (flow.forward_bytes + flow.backward_bytes)/(flow.forward_packets + flow.backward_packets)
            
        outstring = ','.join([str(time), 
                              str(key),
                              str(flow.inport),
                              str(flow.l4proto),
                              str(flow.l4dst),
                              str(flow.forward_packets),
                              str(flow.backward_packets), 
                              str(flow.forward_bytes),
                              str(flow.backward_bytes),
                              str(round(statistics.mean(flow.forward_packets_IAT_list), 4)), 
                              str(round(statistics.pstdev(flow.forward_packets_IAT_list), 4)),
                              str(round(max(flow.forward_packets_IAT_list), 4)),
                              str(round(min(flow.forward_packets_IAT_list), 4)), 
                              str(round(statistics.mean(flow.backward_packets_IAT_list), 4)), 
                              str(round(statistics.pstdev(flow.backward_packets_IAT_list), 4)),
                              str(round(max(flow.backward_packets_IAT_list), 4)),
                              str(round(min(flow.backward_packets_IAT_list), 4)),
                              str(flow.forward_psh_flags),
                              str(flow.backward_psh_flags),
                              str(flow.forward_urg_flags),
                              str(flow.backward_urg_flags),
                              str(avg_pkt_size),
                              str(avg_fwd_size),
                              str(avg_bwd_size)])
                              
        f.write(outstring+'\n')

def ryu_run(proc, f=None):
    while True:
        out = proc.stdout.readline()
        if out == '' and proc.poll() != None:
            break
        if out != '' and out.startswith(b'Entry'):
            fields = out.split(b'\t')[1:]
            fields = [f.decode(encoding='utf-8', errors='strict') for f in fields]
                
            unique_id = hash(''.join([fields[1], fields[3], fields[4], fields[5], fields[6], fields[7]]))
            if unique_id in flows.keys():
                flows[unique_id].update_forward(int(fields[9]),int(fields[10]),int(fields[11]),int(fields[12]),int(fields[0]))
            else:
                rev_id = hash(''.join([fields[1], fields[4], fields[3], fields[5], fields[7], fields[6]]))
                if rev_id in flows.keys():
                    flows[rev_id].update_backward(int(fields[9]),int(fields[10]),int(fields[11]),int(fields[12]),int(fields[0]))
                else:
                    flows[unique_id] = Flow(int(fields[0]), fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8], int(fields[9]), int(fields[10]), int(fields[11]), int(fields[12]))
            
def alarm_handler(signum, frame):
    print("Data collected successfully.")
    raise Exception()

if __name__ == '__main__':
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(TIMEOUT)
    try:
        headers = 'Timestamp,FlowID,In Port,L4 Protocol,L4 Dest,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Average Packet Size,Avg Fwd Segment Size,Avg Bwd Segment Size\n'
        with open('captured_data.csv','w') as f:
            f.write(headers)
            ryu_run(proc, f=f)
    except Exception:
        print("Outputting to file...")
        with open('captured_data.csv','a') as f:
            printflows(f, time=datetime.utcnow().strftime('%s'))
        print("Output successful.")
        print("Exiting.")
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        f.close()
    sys.exit();
                    
        
