import scapy.all as scapy 

def writePcap(packet):
    scapy.wrpcap("Scapy_2.pcap", packet, append=True)

def getIps():
    packets = scapy.rdpcap("Scapy_2.pcap")
    ips = {}
    for pkt in packets:
        pkt_tmp = str(pkt.summary())
        pkt_tmp = pkt_tmp.split()[5:8:2]
        pkt_check_ip = pkt_tmp[0][0]

        if pkt_check_ip.isdigit() != True:
            continue
 
        ip_src = "IP src = " + pkt_tmp[0].split(':')[0]
        ip_dst = pkt_tmp[1].split(':')[0]

        if ip_src not in ips:
            ips[ip_src] = set()
        ips[ip_src].add(ip_dst) 
    
    return ips

packet = scapy.sniff(prn=writePcap)
ips = getIps()
for ip_src, ip_dst in ips.items():
    print(f"{ip_src} -> {', '.join(ip_dst)}")