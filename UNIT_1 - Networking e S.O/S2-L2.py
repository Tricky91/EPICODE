def moltiplicazione():
	primoValore = float(input("Inserisci il primo valore da moltiplicare: "))
	secondoValore = float(input("Inserisci il secondo valore da moltiplicare: "))
	
	prodotto = primoValore * secondoValore

	print("Il risultato della moltiplicazione e':", prodotto)
	return prodotto


def prendiValori():
	grandezza = int(input("Inserisci il numero di valori di cui vuoi calcolare la media: "))
	valori = []

	for i in range(grandezza):
		elemento = float(input("Inserisci il valore " + str(i+1) + ": "))
		valori.append(elemento)

	print("La media aritmetica dei valori che hai inserito e':", calcoloMedia(valori))


def calcoloMedia(listaValori):
	totale = 0
	for i in range(len(listaValori)):
		totale += listaValori[i]

	return totale/len(listaValori)



moltiplicazione()
prendiValori()
