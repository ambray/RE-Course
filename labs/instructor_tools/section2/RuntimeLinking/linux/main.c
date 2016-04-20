#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

__attribute__((visibility("default"))) int exported(int c)
{
    FILE* fh = NULL;

    if(NULL == (fh = fopen("success.txt", "w"))) {
       printf("Failed to open file for writing! %s\n", strerror(errno));
       return errno;
    }

    fprintf(fh, "%s : %d", "Success!", c);

    fclose(fh);
    
    return 0;
}
