#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int browsers()
{
    printf("CHROME:\tWhat are we!?\n");
    printf("\tSAFARI:\t\t\tBrowers!\n\tINTERNET EXPLORER:\n\tFIREFOX:\t\tBrowsers!\n\tOPERA:\t\t\tBrowsers!\n\n");
    printf("CHROME:\tWhat do we want!?\n");
    printf("\tSAFARI:\t\t\tSpeed!\n\tINTERNET EXPLORER:\t\t\n\tFIREFOX:\t\tSpeed!\n\tOPERA:\t\t\tSpeed!\n\n");
    printf("CHROME:\t When do we want it!?\n");
    printf("\tSAFARI:\t\t\tNow!\n\tINTERNET EXPLORER:\n\tFIREFOX:\t\tNow!\n\tOPERA:\t\t\tNow!\n\n");
    printf("CHROME:\t\n");
    printf("\tSAFARI:\n\tINTERNET EXPLORER:\t\t\n\tFIREFOX:\t\t\n\tOPERA:\t\t\n\n");
    printf("CHROME:\t\n");
    printf("\tSAFARI:\n\tINTERNET EXPLORER:\tBrowsers!\n\tFIREFOX: \n\tOPERA:\n\n");
	
    return 0;
}

int name() {
	char * line = (char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100), * linep = line;
    size_t lenmax = 100, len = lenmax;
    char* linen = NULL;
    char c;

    if(line == NULL)
        return -1;

	fprintf(stdout, "Enter your name: ");
    while(1) {
        c = (char)fgetc(stdin);
        if(c == '\n')
            break;

        if(--len == 0) {
            len = lenmax;
            linen = (char *) HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, linep, lenmax *= 2);

            if(linen == NULL) {
                HeapFree(GetProcessHeap(), 0, linep);
                return -1;
            }
            line = linen + (line - linep);
            linep = linen;
        }

        if((*line++ = c) == '\n')
            break;
    }
    *line = '\0';
	
	fprintf(stdout, "%s is not my name.", linep);
	
    return 0;
}

int __cdecl main(int argc, char** argv)
{
	browsers();

	return name();
}