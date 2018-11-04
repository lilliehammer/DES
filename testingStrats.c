#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef uint32_t SUBKEYTYPE;
typedef uint64_t BLOCKTYPE;


int main(int argc, char **argv){
	
	//BLOCKTYPE to play around with
	BLOCKTYPE mainBlock = *((uint64_t*) "abcdefgh") ;
	printf("%lx\n", mainBlock);
	
	
	SUBKEYTYPE rightHalfOld = mainBlock & 0x00000000ffffffff; //TODO: FIXME
	printf("%x\n", rightHalfOld);
	
	
   return 0;
}

