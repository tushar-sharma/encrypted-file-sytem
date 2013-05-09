//Modified 1.0
#include <stdio.h>
#include "myencrypt.h"

int main(int argc, char **argv) 
{
    char path[256];

    getcwd(path, sizeof(path));
    char buffer[256];
    snprintf(buffer, sizeof buffer, "%s/%s", path, argv[2]);

    printf(" full path 1.0 %s\n", buffer);

    if (strcmp(argv[1],"-e") == 0) { 
        myencrypt(1, buffer, argv[3]);   // 1 for encryption 
    } else {
        myencrypt(0, buffer, argv[3]);   // 0 for decryption
    }

    return 0;
}
