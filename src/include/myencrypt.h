// Modified 1.2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <lib.h>
#include <errno.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/wait.h>


int myencrypt(int mode, const char* name, const char *password)
{
   message m;
    
   m.m7_i1 = mode;
   m.m7_p1 = (char*) name;
   m.m7_p2 = (char*) password;
   m.m7_i2 = strlen(name) + 1;
   m.m7_i3 = strlen(password) + 1;

    //calling MYENCRYPT syscall
   _syscall(VFS_PROC_NR, MYENCRYPT, &m);
 
         return 0;
}
