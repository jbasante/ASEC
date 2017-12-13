#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "sha256.h"

/*********************** FUNCTION DEFINITIONS ***********************/

//This is the message that is received by ECU A
char *testtext = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/*This is the maximum length of message you can hash with this algorithm (135 characters)
*abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfgh
*/
int main()
{
  
	if (!hashAndCheck(testtext)){
	  printf("Hashes don't match. Red lights.\n");
	}
	else{
	  printf("Yeeey! Hashes match. Green Lights.\n");
	}

	return(0);
}
