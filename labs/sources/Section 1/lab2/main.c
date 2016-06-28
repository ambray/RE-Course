#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>



int __cdecl main(int argc, char* argv[], char* envp[]) 
{
    char buf[MAX_PATH + 1] = {0};
    DWORD value = 0;
    char* tmp = NULL;

    if(argc < 3)
        return -1;

    if(0 == (value = strtoul(argv[1], NULL, 0)))
        return -2;

    tmp = argv[2];
    if(value != strlen(tmp))
        return -3;

    MessageBoxA(NULL, "[*] Success!", "Success", MB_OK);
    
    return 0;
}