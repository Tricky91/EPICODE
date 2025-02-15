#include <stdio.h>

int main() {
	float primoNumero, secondoNumero; //Dichiaro due variabili di tipo float

	printf("Inserisci il primo valore: ");
	scanf("%f", &primoNumero); //Salvo il primo valore inserito nella variabile primoNumero

	printf("Inserisci il secondo valore: ");
	scanf("%f", &secondoNumero); //Salvo il secondo valore nella variabile secondoNumero

	printf("%.02f * %.02f = %.2f\n", primoNumero, secondoNumero, primoNumero * secondoNumero);

	return 0;
}
