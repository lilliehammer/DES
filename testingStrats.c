#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef uint32_t SUBKEYTYPE;
typedef uint64_t BLOCKTYPE;

uint64_t init_perm[] = {
	58,50,42,34,26,18,10,2,
	60,52,44,36,28,20,12,4,
	62,54,46,38,30,22,14,6,
	64,56,48,40,32,24,16,8,
	57,49,41,33,25,17,9,1,
	59,51,43,35,27,19,11,3,
	61,53,45,37,29,21,13,5,
	63,55,47,39,31,23,15,7
};

int final_perm[] = {
	40,8,48,16,56,24,64,32,
	39,7,47,15,55,23,63,31,
	38,6,46,14,54,22,62,30,
	37,5,45,13,53,21,61,29,
	36,4,44,12,52,20,60,28,
	35,3,43,11,51,19,59,27,
	34,2,42,10,50,18,58,26,
	33,1,41,9, 49,17,57,25
};

void addbit(uint64_t *to, uint64_t from, uint64_t fromPos, int toPos) {
	if(((from << (fromPos)) & 0x8000000000000000) != 0)
        *to += (0x8000000000000000 >> toPos);
	
}

int main(int argc, char **argv){
	
	
	//BLOCKTYPE to play around with
	BLOCKTYPE mainBlock = *((uint64_t*) "abcdefgh") ;
	printf("ONE: %lx\n", mainBlock);
	int i;
	for (i = 0; i < 8; i++) {
		SUBKEYTYPE d = ((mainBlock >> (i*8)) & 0x00000000000000ff);
		char c = d ;
		
		//sprintf(c, "%d", (d += 48));
		printf("TWO: %x %c\n", d, c);
	}
	
	
	//char c = (char) ((mainBlock << 1) & 0xf000000000000000);
	
	return 1;




	
	
	SUBKEYTYPE leftHalfOld = (mainBlock >> 32);
	SUBKEYTYPE rightHalfOld = mainBlock & 0x00000000ffffffff; 
	printf("Left: %x Right %x\n", leftHalfOld, rightHalfOld);
	
	BLOCKTYPE putTogether = 0;
	
	putTogether += rightHalfOld;
	//putTogether >> 32;
	BLOCKTYPE rightNew = 0 + rightHalfOld;
	rightNew = rightNew << 32;
	putTogether += rightNew;
	//putTogether += (rightHalfOld << 32);
	printf("%lx\n", putTogether);
	

	
	
   return 0;
}

