import sys
import subprocess
import signal
import os
import statistics
from datetime import datetime

import numpy as np
import prettytable

command = "cd /home/marek/ryu && python3 ./bin/ryu-manager /home/marek/monitor.py"
flows = {}
TIMEOUT_SECONDS = 120 #default

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
        
        # Basic features
        self.forward_packets = packets
        self.forward_bytes = bytes
        
        self.forward_packets_delta = 0
        self.forward_packets_delta_list = []
        self.forward_packets_IAT_list = [0]
        self.forward_bytes_delta = 0
        
        # Extended features
        self.forward_psh_flags = psh
        self.forward_urg_flags = urg
        
        # Basic features
        self.backward_packets = 0
        self.backward_bytes = 0
        
        self.backward_packets_delta = 0
        self.backward_packets_delta_list = []
        self.backward_packets_IAT_list = [0]
        self.backward_bytes_delta = 0
        
        # Extended features
        self.backward_psh_flags = 0
        self.backward_urg_flags = 0
        
        # Calculated features
        self.fwd_iat_mean = 0 
        self.fwd_iat_std = 0
        self.fwd_iat_max = 0
        self.fwd_iat_min = 0 
        self.bwd_iat_mean = 0 
        self.bwd_iat_std = 0
        self.bwd_iat_max = 0
        self.bwd_iat_min = 0
        self.psh_flag_count = self.forward_psh_flags + self.backward_psh_flags
        self.urg_flag_count = self.forward_urg_flags + self.backward_urg_flags
        self.avg_pkt_size = 0
        self.avg_fwd_size = 0
        self.avg_bwd_size = 0
        
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
        
        self.forward_psh_flags = psh
        self.forward_urg_flags = urg
        
        self.calculate_features()
    
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
        
        self.backward_psh_flags = psh
        self.backward_urg_flags = urg
        
        self.calculate_features()
        
    def calculate_features(self):        
        self.fwd_iat_mean = round(statistics.mean(self.forward_packets_IAT_list), 4) 
        self.fwd_iat_std = round(statistics.pstdev(self.forward_packets_IAT_list), 4)
        self.fwd_iat_max = round(max(self.forward_packets_IAT_list), 4)
        self.fwd_iat_min = round(min(self.forward_packets_IAT_list), 4) 
        self.bwd_iat_mean = round(statistics.mean(self.backward_packets_IAT_list), 4) 
        self.bwd_iat_std = round(statistics.pstdev(self.backward_packets_IAT_list), 4)
        self.bwd_iat_max = round(max(self.backward_packets_IAT_list), 4)
        self.bwd_iat_min = round(min(self.backward_packets_IAT_list), 4)
        
        self.psh_flag_count = self.forward_psh_flags + self.backward_psh_flags
        self.urg_flag_count = self.forward_urg_flags + self.backward_urg_flags
        
        avg_pkt_size = 0
        avg_fwd_size = 0
        avg_bwd_size = 0
        if (self.forward_packets > 0):
            avg_fwd_size = (self.forward_bytes / self.forward_packets)
        if (self.backward_packets > 0):
            avg_bwd_size = (self.backward_bytes / self.backward_packets) 
        if (self.forward_packets > 0 or self.backward_packets > 0):
            avg_pkt_size = (self.forward_bytes + self.backward_bytes)/(self.forward_packets + self.backward_packets)
            
        self.avg_pkt_size = avg_pkt_size
        self.avg_fwd_size = avg_fwd_size
        self.avg_bwd_size = avg_bwd_size
            
def print_table(ml_model):
    table = PrettyTable()
    table.field_names = ["ID", "ETH SRC", "ETH DST", "L4 PROTO", "L4 SRC", "L4 DST", "PSH COUNT", "CLASS"]
    
    for key, flow in flows.items():
        features = [flow.forward_packets,
                    flow.backward_packets,
                    flow.forward_bytes,
                    flow.backward_bytes,
                    flow.fwd_iat_mean,
                    flow.fwd_iat_std,
                    flow.fwd_iat_max,
                    flow.fwd_iat_min,
                    flow.bwd_iat_mean,
                    flow.bwd_iat_std,
                    flow.bwd_iat_max,
                    flow.bwd_iat_min,
                    flow.forward_psh_flags,
                    flow.backward_psh_flags,
                    flow.forward_urg_flags,
                    flow.backward_urg_flags,
                    flow.psh_flag_count,
                    flow.urg_flag_count,
                    flow.avg_pkt_size,
                    flow.avg_fwd_size,
                    flow.avg_bwd_size]
                    
        label = ml_model.predict(features)
        x.add_row([key, flow.ethsrc, flow.ethdst, flow.l4proto, flow.l4src, flow.l4dst, flow.psh_flag_count, label[0]])
        
    print(table)
    
def print_flows(f, time):
    for key, flow in flows.items():            
        outstring = ','.join([str(time), 
                              str(key),
                              str(flow.inport),
                              str(flow.l4proto),
                              str(flow.l4dst),
                              str(flow.forward_packets),
                              str(flow.backward_packets), 
                              str(flow.forward_bytes),
                              str(flow.backward_bytes),
                              str(flow.fwd_iat_mean), 
                              str(flow.fwd_iat_std),
                              str(flow.fwd_iat_max),
                              str(flow.fwd_iat_min), 
                              str(flow.bwd_iat_mean), 
                              str(flow.bwd_iat_std),
                              str(flow.bwd_iat_max),
                              str(flow.bwd_iat_min),
                              str(flow.forward_psh_flags),
                              str(flow.backward_psh_flags),
                              str(flow.forward_urg_flags),
                              str(flow.backward_urg_flags),
                              str(flow.psh_flag_count),
                              str(flow.urg_flag_count),
                              str(flow.avg_pkt_size),
                              str(flow.avg_fwd_size),
                              str(flow.avg_bwd_size)])
                              
        f.write(outstring+'\n')

def print_help():
    print('For collecting data into a .csv file, use "sudo python3 classifier_script.py capture [timeout_in_seconds]"')
    print('For real-time flow classification, use "sudo python3 classifier_script.py [rfc | gbc | dt]"')
    return

def ryu_run(proc, ml_model=None):
    time = 0
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
            
            if ml_model is not None:
                if time%10 == 0:
                    print_table(ml_model)
            time += 1
                    
            
def alarm_handler(signum, frame):
    print("Data collected successfully.")
    raise Exception()

if __name__ == '__main__':
    arguments = ['help', 'capture', 'rfc', 'gbc', 'dt']
    
    if (len(sys.argv) < 2 or sys.argv[1] == 'help'):
        print_help()
        sys.exit()
    
    if (sys.argv[1] not in arguments):
        print('ERROR: Unknown argument.')
        sys.exit()
    
    if (sys.argv[1] == 'capture'):
        monitor_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if (len(sys.argv) == 3 and sys.argv[2].isdigit()): 
            TIMEOUT_SECONDS = int(sys.argv[2])
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(TIMEOUT_SECONDS)
        try:
            headers = 'Timestamp,FlowID,In Port,L4 Protocol,L4 Dest,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,PSH Flag Count,URG Flag Count,Average Packet Size,Avg Fwd Segment Size,Avg Bwd Segment Size\n'
            with open('captured_data.csv','w') as f:
                f.write(headers)
                ryu_run(monitor_process)
        except Exception:
            print("Outputting to file...")
            with open('captured_data.csv','a') as f:
                print_flows(f, time=datetime.utcnow().strftime('%s'))
            print("Output successful.")
            print("Exiting.")
            os.killpg(os.getpgid(monitor_process.pid), signal.SIGTERM)
            f.close()
        sys.exit();        
    else:
        monitor_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if (sys.argv[1] == 'rfc'):
            model_file = open('RandomForestClassifier', 'rb')
        if (sys.argv[1] == 'gbc'):
            model_file = open('GradientBoosterClassifier', 'rb')
        if (sys.argv[1] == 'dt'):
            model_file = open('DecistionTreeClassifier', 'rb')
        ml_model = pickle.load(model_file)
        model_file.close()
        ryu_run(monitor_process, ml_model = ml_model)
    sys.exit()
                    
        
