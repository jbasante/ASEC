#include <stdio.h>
#include <stdint.h>
#include "sha.h"
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <memory.h>


//this will be replaced with the message coming from ECU A
char *test_message = "abcdefujhdtendmjjjijsiskloskksewabcdefgabcerbadsondaughterchildparentmadeBarimakojokyereasantejoseph";

int main()
{
    SHA1Context sha;
    int i, j;
    
    MessageContent *message1;

    if((message1->message = (char *)malloc(sizeof(char *)*strlen(test_message))) == NULL){;
        printf("Memory allocation failed\n");
        return 0;
    }
    
    if(strcpy(message1->message, test_message) == NULL){
      return 0;
    }
        
    for (j = 0; j < 1; j++){
        if(CheckMessageHash(message1, &sha)){
          printf("Flashing green lights. Do something with arduino.\n");
        }
        else{
          printf("No flashing red lights. Do something with arduino.\n");
        }
    }
   
    free(message1->message);

    return 0;
}
