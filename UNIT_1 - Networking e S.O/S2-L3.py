import re #importo libreria per la funzione parole


def bandName():
	citta = input("Inserisci il nome della citta' di origine della band: ")
	animale = input("Inserisci il nome dell'animale domestico del frontman della band: ")
	print(f"Il nome della vostra band potrebbe essere: {citta} {animale}")


def parole():
	frase = input("Inserisci la frase da analizzare: ")
	risultato = {} #Dizionario finale
	nuovaLista = [] #Lista temporanea per il confronto

	miaFrase = re.sub(r"[^\w\s]", "", frase.lower()) #Elimina la punteggiatura

	miaFrase = miaFrase.split(" ") #Creo lista di parole contenute nella frase

	for i in range(len(miaFrase)): #Creo il dizionario e aggiorno lista confronto
		if miaFrase[i] not in nuovaLista:
			risultato[miaFrase[i]] = miaFrase.count(miaFrase[i])
			nuovaLista.append(miaFrase[i])

	print(risultato)



bandName()
parole()
