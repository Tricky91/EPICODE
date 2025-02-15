def perimetro():
	print("""*** Benvenuto nel programma per calcolare il perimetro di una figura geometrica. ***\n
Sono in grado di calcolare il perimetro del triangolo, quadrato, rettangolo e cerchio.
Inserisci il numero associato alla fugura di tuo interesse:""")
	
	#Faccio scegliere all'utente la figura geometrica
	scelta = int(input("1 - Triangolo\t 2 - Quadrato\t 3 - Rettangolo\t 4 - Cerchio\n>>> "))

	if (scelta == 1):
		return triangolo()
	elif (scelta == 2):
		return quadrato()
	elif (scelta == 3):
		return rettangolo()
	elif (scelta == 4):
		return cerchio()
	else:
		print("Hai inserito un numero non valido, riprova!")

def triangolo():
	print("Hai scelto di calcolare il perimetro del triangolo")
	
	#Chiedo se il triangolo e' equilatero
	equilatero = input("Il triangolo e' equilatero? (si o no) ")

	#Se il triangolo e' equilatero
	if (equilatero.lower() == "si" or equilatero.lower() == "sì" or equilatero.lower() =="s" or equilatero.lower() == "yes" or equilatero.lower() == "y"):
		lato = int(input("Inserisci la dimensione del lato: "))
		perimetro = lato*3
		print(f"Il perimetro del tuo triangolo e' {perimetro}")

	elif (equilatero.lower() == "no" or equilatero.lower() == "n" or equilatero.lower() == "not"):
		isoscele = input("Il triangolo e' isoscele? (si o no) ")
		#Verifico se il triangolo e' isoscele
		if (isoscele.lower() == "si" or isoscele.lower() == "sì" or isoscele.lower() == "s" or isoscele.lower() == "yes" or isoscele.lower() == "y"):
			lato1 = int(input("Inserisci la dimensione dei lati uguali: "))
			lato2 =  int(input("Inserisci la dimensione del terzo lato: "))
			perimetro = (lato1 * 2) + lato2
			print(f"Il perimetro del tuo triangolo e' {perimetro}")
		#Il triangolo e' scaleno
		elif (isoscele.lower() == "no" or isoscele.lower() == "n" or isoscele.lower() == "not"):
			lato1 = int(input("Il triangolo e' scaleno, inserisci la dimensione del primo lato: "))
			lato2 = int(input("Inserisci la dimensione del secondo lato: "))
			lato3 = int(input("Inserisci la dimensione del tezo lato: "))
			perimetro = lato1 + lato2 + lato3
			print(f"Il perimetro del tuo triangolo e' {perimetro}")
		else:
			print("Errore nell'input, riprova!")

	else:
		print("Errore nell'input, riprova!")

def quadrato():
	print("Hai scelto di calcolare il perimetro del quadrato")
	lato = int(input("Inserisci la dimensione del lato del quadrato: "))
	print("Il perimetro del tuo quadrato e': ", lato*4)

def rettangolo():
	print("Hai scelto di calcolare il perimetro del rettangolo")

	base = int(input("Inserisci la dimensione della base del rettangolo: "))
	altezza = int(input("Inserisci la dimensione dell'altezza del rettangolo: "))

	print("Il perimetro del tuo rettangolo e': ", (base*2) + (altezza * 2))

def cerchio():
	print("Hai scelto di calcolare la circonferenza del cerchio")

	pi = 3.14
	raggio = int(input("Inserisci la lunghezza del raggio della circonferenza: "))

	print("La circonferenza del tuo cerchio e': ", 2 * pi * raggio)


perimetro()
