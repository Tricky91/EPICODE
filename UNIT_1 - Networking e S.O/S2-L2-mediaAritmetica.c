#include <stdio.h>

float media(float valori[], int grandezza);

int main() {

	int grandezza;

	printf("Inserisci il numero di valori di cui fare la media aritmetica: ");
	scanf("%d", &grandezza);

	float valori[grandezza];

	printf("Media aritmetica dei valori inseriti: %.2f\n", media(valori, grandezza));

	return 0;
}

float media(float valori[], int grandezza)  {

	float totale = 0, media;

	for (int i = 0; i < grandezza; i++) {
		printf("Inseerisci il valore %d: ", i+1);
		scanf("%f", &valori[i]);
		totale += valori[i];
	}

	media = totale / grandezza;

	return media;
}
