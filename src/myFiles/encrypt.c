#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) 
{ 

    FILE *fp;
    int c;
    int key = 0;

    if (argc < 4) {
        printf("Less argument count \n");
	printf(" <e/d> <key> <filename>\n");
	exit(EXIT_FAILURE);
    }
 
    for (int i = 0; i < strlen(argv[2]); i++) {
        key += (int) argv[2][i];
    }

    key = (key % 5);

    fp = fopen(argv[3], "r");

    if (fp == NULL) {
        printf("Unable to open the file \n");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    long length = ftell(fp);

    fseek(fp, 0, SEEK_SET);

    char *mystring = malloc((length + 1) * sizeof(char));
 
    if (mystring == NULL) {
        perror("Not enough memory\n");
	exit(EXIT_FAILURE);
    }

    long offset = 0;
    while (!feof(fp) && offset < length) {
        //printf("reading from offset %d \n", offset);
	offset += fread(mystring + offset, sizeof(char), length - offset, fp);
    }

    mystring[offset] = '\0';
    //printf("%s", mystring);

    fclose(fp);

    fp = fopen(argv[3], "w");

    /*for (int i = 0; i < strlen(mystring) - 1; i++) {
        mystring[i] = (int) mystring[i] + 1;    
    }*/

    
    for (char *ch = mystring; *ch != '\0'; ch++) {
        if (*argv[1] == 'e') { //encryption
	    //printf(" %d ", (int)*ch);
	    if (*ch >= 'a' && *ch <= 'z') {

                 *ch = (int) *ch + key;

		 /*if (*ch < 0)
		     *ch = -(*ch) + 1;
               
	         if (*ch == 0)
		     *ch = 128;
		*/ 
		 while (*ch > 'z') 
		     *ch  = ((int) *ch -  122)+ 97 - 1;
                // printf(" %d ", (int) *ch);
 
	    }

	    else if (*ch >= 'A' && *ch <= 'Z') {
                 *ch = (int) *ch + key;
		 
		 while (*ch > 'Z') 
		     *ch  = ((int) *ch - 90) + 65 - 1;
	    }
	    
	    else {
                *ch =  (int) *ch + key;
	    }

	    //printf(" %d   ", (int) *ch);
	}

	else {  //decryption
            if (*ch >= 'a' && *ch <= 'z') {
                 *ch = (int) *ch - key;
		 
		 while (*ch < 'a') 
		     *ch  = (int) *ch + 26;

		 while (*ch > 'z') 
		     *ch  = (int) *ch - 26;
	
	    }

	    else if (*ch >= 'A' && *ch <= 'Z') {
                 *ch = (int) *ch - key;
		 
		 while (*ch < 'A') 
		     *ch  = (int) *ch + 26;

		 while (*ch > 'Z') 
		     *ch  = (int) *ch - 26;
	    }

	    else {
                *ch =  (int) *ch - key;
	    }
	}
    }
 
    /*for (int i = 0; i < strlen(mystring); i++) 
         printf(" %d ", (int)mystring[i]);  */
    //printf("%s", mystring);
 
    fseek(fp, 0, SEEK_SET);

    fwrite(mystring, length, sizeof(char), fp);

    fclose(fp);

    return 0;
}
