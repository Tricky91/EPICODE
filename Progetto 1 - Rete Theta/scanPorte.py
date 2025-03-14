import socket

target = "192.168.20.2"	#Target
portRange = "1-500"	#Porte
timeout = 1		#Timeout per la connessione

lowPort = int(portRange.split('-')[0])
highPort = int(portRange.split('-')[1])

print(f"Start scanning host {target}, from port {lowPort} to {highPort}...")

portOpen = []		#Lista porte aperte
portFiltered = []	#Lista porte filtrate
portClosed = []		#Lista porte chiuse

#Scan delle porte
for port in range(lowPort, highPort + 1):
	#Apertura del socket per controllo della porta
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	#Timeout per la connessione
	s.settimeout(timeout)

	#Tento la connessione includendo le eccezioni
	status = s.connect_ex((target, port))

	if status == 0:	#Porta aperta
		portOpen.append(port)
	elif status == 111:	#Porta chiusa
		portClosed.append(port)
	else:
		portFiltered.append(port)

s.close()	#Chiusura del socket

#Output finale
print("\n\nScanning complete.")

if len(portOpen) > 0:
	print(f"Total open ports: {len(portOpen)}")
	input("Press ENTER to show the list of open ports...\n")
	for port in portOpen:
		print(f"*** Port {port} - OPEN ***")
	for port in portFiltered:
		print(f"Port {port} - FILTERED")
	for port in portClosed:
		print(f"Port {port} - closed")
else:
	print("No open ports found.")
