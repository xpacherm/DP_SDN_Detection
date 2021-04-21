import sys
import subprocess
import signal
import os
import statistics

command = "cd /home/marek/ryu && python3 ./bin/ryu-manager /home/marek/monitor.py"
flows = {}
MINUTES = 1 #Training data collecting length
TIMEOUT = 30 * MINUTES

class Flow:
    def __init__(self, time_start, datapath, inport, ethsrc, ethdst, outport, packets, bytes):
        self.time_start = time_start
        self.datapath = datapath
        self.inport = inport
        self.ethsrc = ethsrc
        self.ethdst = ethdst
        self.outport = outport
        
        self.forward_packets = packets
        self.forward_bytes = bytes
        self.forward_packets_delta = 0
        self.forward_packets_delta_list = []
        self.forward_packets_IAR_list = [0]
        self.forward_bytes_delta = 0
        self.forward_status = 1
        self.forward_last_time = time_start
        
        self.backward_packets = 0
        self.backward_bytes = 0
        self.backward_packets_delta = 0
        self.backward_packets_delta_list = []
        self.backward_packets_IAR_list = [0]
        self.backward_bytes_delta = 0
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
    def update_forward(self, packets, bytes, current_time):
        self.forward_packets_delta_list.append(self.forward_packets_delta)
        self.forward_packets_delta = packets - self.forward_packets
        
        if (len(self.forward_packets_delta_list) >= 2):
            if (self.forward_packets_delta_list[-1] != 0):
                for i in range(len(self.forward_packets_delta_list)-2, -1, -1):
                    if (self.forward_packets_delta_list[i] != 0):
                        break
                zeroes_found = len(self.forward_packets_delta_list) - i - 2
                if (zeroes_found != 0):
                    self.forward_packets_IAR_list.append(zeroes_found)
                for j in range(self.forward_packets_delta_list[-1]):
                    self.forward_packets_IAR_list.append(1/(self.forward_packets_delta_list[-1]))
        
        self.forward_packets = packets
        
        self.forward_bytes_delta = bytes - self.forward_bytes
        self.forward_bytes = bytes
        
        self.forward_last_time = current_time
        
        if (self.forward_packets_delta == 0 or self.forward_bytes_delta == 0):
            self.forward_status = 0
        else:
            self.forward_status = 1
    
    def update_backward(self, packets, bytes, current_time):
        self.backward_packets_delta = packets - self.backward_packets
        self.backward_packets_delta_list.append(self.backward_packets_delta)
        
        if (len(self.backward_packets_delta_list) >= 2):
            if (self.backward_packets_delta_list[-1] != 0):
                for i in range(len(self.backward_packets_delta_list)-2, -1, -1):
                    if (self.backward_packets_delta_list[i] != 0):
                        break
                print(i)
                zeroes_found = len(self.backward_packets_delta_list) - i - 2
                if (zeroes_found != 0):
                    self.backward_packets_IAR_list.append(zeroes_found)
                for j in range(self.backward_packets_delta_list[-1]):
                    self.backward_packets_IAR_list.append(1/(self.backward_packets_delta_list[-1]))
        
        self.backward_packets = packets
        
        self.backward_bytes_delta = bytes - self.backward_bytes
        self.backward_bytes = bytes
        
        self.backward_last_time = current_time
        
        if (self.backward_packets_delta == 0 or self.backward_bytes_delta == 0):
            self.backward_status = 0
        else:
            self.backward_status = 1
            
def printflows(f, time):
    for key,flow in flows.items():
        outstring = ','.join([str(time), str(key), str(flow.forward_packets), str(flow.forward_bytes), str(flow.forward_packets_delta), str(flow.forward_bytes_delta), str(flow.backward_packets), str(flow.backward_bytes), str(flow.backward_packets_delta), str(flow.backward_bytes_delta), str(round(statistics.pstdev(flow.forward_packets_IAR_list), 3)), str(round(statistics.pstdev(flow.backward_packets_IAR_list), 3))])
        print(outstring)
        f.write(outstring+'\n')

def ryu_run(proc, f=None):
    while True:
        out = proc.stdout.readline()
        print(out)
        if out == '' and proc.poll() != None:
            break
        if out != '' and out.startswith(b'data'):
            fields = out.split(b'\t')[1:]
            fields = [f.decode(encoding='utf-8', errors='strict') for f in fields]
                
            unique_id = hash(''.join([fields[1], fields[3], fields[4]]))
            if unique_id in flows.keys():
                flows[unique_id].update_forward(int(fields[6]),int(fields[7]),int(fields[0]))
            else:
                rev_id = hash(''.join([fields[1], fields[4], fields[3]]))
                if rev_id in flows.keys():
                    flows[rev_id].update_backward(int(fields[6]),int(fields[7]),int(fields[0]))
                else: flows[unique_id] = Flow(int(fields[0]), fields[1], fields[2], fields[3], fields[4], fields[5], int(fields[6]), int(fields[7]))
            printflows(f, time=fields[0])
            
def alarm_handler(signum, frame):
    print("Data collected successfully.")
    raise Exception()

if __name__ == '__main__':
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(TIMEOUT)
    try:
        headers = 'Timestamp,FlowID,Forward Packets,Forward Bytes,Forward Packets Delta,Forward Bytes Delta,Backward Packets,Backward Bytes,Backward Packets Delta,Backward Bytes Delta,Forward IAT,Backward IAT\n'
        with open('captured_data.csv','w') as f:
            f.write(headers)
            ryu_run(proc, f=f)
    except Exception:
        print("Exiting")
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        f.close()
    sys.exit();
                    
        
