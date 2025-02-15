import socket
import random
import string

# Funzione per generare dati casuali alfanumerici di 1KB
def generate_random_data(size_kb):
    # Genera una stringa alfanumerica casuale di caratteri
    random_string = ''.join(random.choices(string.digits, k=size_kb * 1016))
    return random_string.encode()  #Restituisce la stringa in UTF-8

#Funzione principale per inviare pacchetti UDP
def send_udp_packets(num_packets, dest_ip, dest_port):
    #Creo un socket UDP (SOCK_DGRAM)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #Genera 1KB di dati alfanumerici
    message = generate_random_data(1)  #1 KB = 1024 byte

    #Invia i pacchetti
    for i in range(num_packets):
        sock.sendto(message, (dest_ip, dest_port))
        print(f"Pacchetto {i + 1} di {num_packets} inviato a {dest_ip}:{dest_port}")

    #Chiudi il socket
    sock.close()
    print(f"Tutti i {num_packets} pacchetti sono stati inviati.")

#Richiesta del numero di pacchetti all'utente
try:
    num_packets = int(input("Quanti pacchetti UDP di 1KB vuoi inviare? "))
    if num_packets <= 0:
        print("Il numero di pacchetti deve essere maggiore di zero.")
    else:
        #Input dell'indirizzo IP e la porta del destinatario
        dest_ip = input("Inserisci l'indirizzo IP target: ")	#Indirizzo IP del destinatario
        dest_port = int(input("Inserisci la porta a cui inviare il pacchetto UDP: "))   #Porta a cui inviare il pacchetto UDP

        #Invia i pacchetti
        send_udp_packets(num_packets, dest_ip, dest_port)
except ValueError:
    print("Per favore inserisci un numero valido di pacchetti.")

