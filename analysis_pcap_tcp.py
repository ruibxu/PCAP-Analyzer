import dpkt
import sys
import socket

# hardcoded sender ip and receiver ip
sender_ip="130.245.145.12"
receiver_ip="128.208.2.198"
# list that stores every tcp flow
tcp_flows = []

# class for TCP flow
class TCP_flow:
   def __init__(self,src_ip,src_port,dst_ip,dst_port,index):
      self.index = index
      self.src_ip = src_ip
      self.src_port = src_port
      self.dst_ip = dst_ip
      self.dst_port = dst_port
      self.throughput = 0
      self.start_time=0
      self.end_time=0
      self.pkt_length=0
      self.sender_transactions = []
      self.receiver_transactions = []
      self.cwnd_count=0
      self.cwnds=[]
      self.triple_duplicate_ack=0 
      self.timeout=0 
      self.connected=False
      self.finished=True
      self.send_fin=False
      self.receiver_prev_transaction=None
      self.retransmission=0
      self.count=0
      self.rtt_start=None
      self.rtt_end=None
      self.receiver_duplicate_ack=0
      self.duplicating=False

# class for one transaction
class Transaction:
   def __init__(self,seq,ack,win,send_time):
      self.seq = seq
      self.ack = ack
      self.win = win
      self.send_time= send_time
      self.response_time= 0
      


# convert ip address field to readable ip address
def inet_to_str(inet):
   try:
      return socket.inet_ntop(socket.AF_INET, inet)
   except ValueError:
      return socket.inet_ntop(socket.AF_INET6, inet)


def main():
   #get the file name
   fileName= sys.argv[1]
   # try to open the file.
   try:
      f = open(fileName, "rb")
   except:
      print("failed to open the file: ", fileName)
      return
   # read pcap file
   pcap = dpkt.pcap.Reader(f)
   # counter for the index of TCP flows
   TCP_flow_count = 0

   # traverse the pcap file
   for ts, buf in pcap:
      #separate them to tcps, and check if they are vaild
      eth = dpkt.ethernet.Ethernet(buf)
      ip = eth.data
      if not isinstance(ip, dpkt.ip.IP):
         print("Non IP Packet type not supported")
         continue
      tcp = ip.data
      if not isinstance(eth.data.data, dpkt.tcp.TCP):
         print("Non TCP Packet type not supported")
         continue

      # get the src_ip, dst_ip,src_port and dst_port.
      src_ip = inet_to_str(ip.src)
      dst_ip = inet_to_str(ip.dst)
      src_port = tcp.sport
      dst_port = tcp.dport
      # the payload length for the current tcp

      pyload_length = len(tcp.data)

      # if the it is send from sender to receiver and is SYN
      if src_ip == sender_ip and dst_ip == receiver_ip:
         if tcp.flags & dpkt.tcp.TH_SYN:
            syn_flag=0
            for flow in tcp_flows:
               # check of port are matched
               if flow.src_port == src_port and flow.dst_port == dst_port:
                  # if this flow is not get response from receiver which is not connected, or it is already finished which means fin of this flow appeared.
                  syn_flag=1
                  if (not flow.connected) and flow.finished:
                     # create a new flow
                     TCP_flow_count+=1
                     tcp_flow = TCP_flow(src_ip, src_port, dst_ip, dst_port,TCP_flow_count)
                     tcp_flow.start_time = ts
                     tcp_flow.finished=False
                     tcp_flows.append(tcp_flow)
                     tcp_flows.pkt_length+=pyload_length
            if syn_flag==0:
               TCP_flow_count+=1
               tcp_flow = TCP_flow(src_ip, src_port, dst_ip, dst_port,TCP_flow_count)
               tcp_flow.start_time = ts
               tcp_flow.finished=False
               tcp_flows.append(tcp_flow)
               tcp_flow.pkt_length+=pyload_length
               tcp_flow.rtt_start=ts
         # check each flow in tcp_flows list
      
      for flow in tcp_flows:
         if src_ip == sender_ip and dst_ip == receiver_ip:
         # if from sender to receiver
            if flow.src_port == src_port and flow.dst_port == dst_port and flow.connected and not flow.finished:
               # if FIN
               if tcp.flags & dpkt.tcp.TH_FIN:
                  flow.send_fin=True
                  flow.pkt_length+=pyload_length
               # if ACK
               elif tcp.flags & dpkt.tcp.TH_ACK :
                  # we make a new transcation, and also check if there are duplicates first
                  transaction=Transaction(tcp.seq,tcp.ack,tcp.win,ts)
                  transaction.send_time=ts
                  t_flag=0

               
                  for t in flow.sender_transactions:
                     #retransmission
                     if transaction.seq == t.seq and transaction.ack == t.ack and transaction.win == t.win:
                        t_flag=1
                        flow.retransmission+=1
                        # check for time out retransmission
                        if (transaction.send_time-t.send_time)>=2*(flow.rtt_end-flow.rtt_start):
                           flow.timeout+=1
                        # check for triple duplicate retransmission
                        elif  flow.receiver_prev_transaction!=None and flow.receiver_prev_transaction.ack==transaction.seq and flow.duplicating:
                           flow.triple_duplicate_ack+=1
                           flow.duplicating=False

                        t.send_time=transaction.send_time
                  # normal ACK case
                  if t_flag==0:

                     if flow.count==0:
                        flow.count=1
                        flow.rtt_end=ts
                     flow.sender_transactions.append(transaction)
                     flow.cwnd_count+=1
                     flow.pkt_length+=pyload_length
                     # Last ACK
                     if flow.send_fin:
                        flow.end_time=ts
                        flow.finished=True
                        flow.connected=False
                        flow.send_fin=False


         # if from receiver to sender
         elif src_ip == receiver_ip and dst_ip == sender_ip:
            # check port
            if flow.src_port == dst_port and flow.dst_port == src_port:
               #if SYN
               if tcp.flags & dpkt.tcp.TH_SYN:
                  flow.connected=True
               #if FIN
               elif tcp.flags & dpkt.tcp.TH_FIN:
                  flow.cwnds.append(flow.cwnd_count)
                  flow.cwnd_count *= 2
               # if ACK packet 
               elif tcp.flags & dpkt.tcp.TH_ACK:
                  flow.cwnds.append(flow.cwnd_count)
                  flow.cwnd_count *= 2
                  transaction=Transaction(tcp.seq,tcp.ack,tcp.win,ts)
                  t_flag=0

                  # check for triple duplicates
                  if flow.receiver_prev_transaction !=None and transaction.ack==flow.receiver_prev_transaction.ack :
                     t_flag=1
                     flow.receiver_duplicate_ack+=1
                  else:
                     flow.receiver_duplicate_ack=0

                  flow.receiver_prev_transaction=transaction

                  if flow.receiver_duplicate_ack==2:
                     flow.duplicating=True

                  # normal ack case, add to transaction list        
                  if t_flag == 0:
                     flow.receiver_transactions.append(transaction)
            
            
            
   f.close()

   # print the sequence number, ACK number, and window size for each TCP flow
   for flow in tcp_flows:
      
      print("TCP Flow #", flow.index)
      print("Source IP:", flow.src_ip, "  Source port:", flow.src_port)
      print("Destination IP:", flow.dst_ip, "  Destination port:", flow.dst_port,"\n")

      print("Transaction #1")
      print("Sender -> Receiver    Sequence number:", flow.sender_transactions[0].seq, "  ACK number:", flow.sender_transactions[0].ack, "  Window size:", flow.sender_transactions[0].win)
      print("Receiver -> Sender    Sequence number:", flow.receiver_transactions[0].seq, "  ACK number:", flow.receiver_transactions[0].ack, "  Window size:", flow.receiver_transactions[0].win,"\n")

      print("Transaction #2")
      print("Sender -> Receiver    Sequence number:", flow.sender_transactions[1].seq, "  ACK number:", flow.sender_transactions[1].ack, "  Window size:", flow.sender_transactions[1].win)
      print("Receiver -> Sender    Sequence number:", flow.receiver_transactions[1].seq, "  ACK number:", flow.receiver_transactions[1].ack, "  Window size:", flow.receiver_transactions[1].win,"\n")
      
      print("Total throughput: {0:.2f} bytes/sec".format(flow.pkt_length/(flow.end_time-flow.start_time)),"\n")

      print(f"Congestion window sizes: {flow.cwnds[0]}, {flow.cwnds[1]}, {flow.cwnds[2]}","\n")

      print(f"Triple duplicate acks retransmissions: ",flow.triple_duplicate_ack)

      print(f"Time outs retransmissions: ",flow.timeout)

      print(f"Other retransmissions: ",flow.retransmission-flow.timeout-flow.triple_duplicate_ack,"\n")

      print(f"Total retransmissions: ",flow.retransmission,"\n")

      print("--------------------------------------","\n")
      
   print("Total TCP flow count: ",TCP_flow_count,"\n")


if __name__ == "__main__":
   main()