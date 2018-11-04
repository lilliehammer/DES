des: DES.c
	clear
	gcc -Wall -g DES.c -o des

test: testingStrats.c
	clear
	gcc -Wall -g testingStrats.c -o testing
