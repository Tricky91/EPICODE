from scapy.all import *

output_file = "catturaUDP.pcap"	#File .pcap salvataggio pacchetti
captured_packets = []

#Funzione di callback per gestire i pacchetti UDP
def packet_callback(packet):
    if packet.haslayer(UDP):  #Verifica se il pacchetto è UDP
        print(f"Pacchetto UDP catturato:")
        print(f"   - Indirizzo sorgente: {packet[IP].src}")
        print(f"   - Indirizzo destinazione: {packet[IP].dst}")
        print(f"   - Porta sorgente: {packet[UDP].sport}")
        print(f"   - Porta destinazione: {packet[UDP].dport}")
        print(f"   - Dati: {packet[UDP].payload}")
        print("-" * 50)

        captured_packets.append(packet)

#Inizia a sniffare sulla rete
def start_sniffer(interface):
    print("Avvio sniffer... (Premi Ctrl+C per fermare)")

    #Sniffa pacchetti UDP sulla rete
    sniff(filter="udp", prn=packet_callback, store=0, iface=interface)

#Iniziamo lo sniffer sulla rete, puoi passare l'interfaccia (es. eth0, wlan0, ecc.)
start_sniffer("eth0")

#Dopo aver terminato lo sniffing, salva i pacchetti in un file .pcap
wrpcap(output_file, captured_packets, append=False)
