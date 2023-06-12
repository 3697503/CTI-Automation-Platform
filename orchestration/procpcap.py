from scapy.all import *

def extract_iocs(pcap_file):
    packets = rdpcap(pcap_file)
    
    ip_iocs = set()
    domain_iocs = set()
    url_iocs = set()

    for packet in packets:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_iocs.add(src_ip)
            ip_iocs.add(dst_ip)

        if packet.haslayer(DNS):
            for query in packet[DNSQR]:
                domain = query.qname.decode()
                domain_iocs.add(domain)

        if packet.haslayer('HTTPRequest'):
            http_request = packet[HTTP]
            if http_request.Method.decode() == "GET":
                url = http_request.Host.decode() + http_request.Path.decode()
                url_iocs.add(url)

    return ip_iocs, domain_iocs, url_iocs

# Usage
pcap_file_path = "test.pcap"
ip_iocs, domain_iocs, url_iocs = extract_iocs(pcap_file_path)

# Print the extracted IOCs
print("IP IOCs:")
for ip in ip_iocs:
    print(ip)

print("Domain IOCs:")
for domain in domain_iocs:
    print(domain)

print("URL IOCs:")
for url in url_iocs:
    print(url)
