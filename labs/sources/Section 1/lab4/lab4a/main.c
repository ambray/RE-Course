#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define STRING_TO_HASH  "This is a test string. Lorem ipsum and stuff."
#define HASH_VALUE      0x40f1e9


void __declspec(dllexport) Lab4a()
{
    char buf[MAX_PATH+1] = {0};
    size_t value = 0;
    char* tmp = NULL;

    tmp = STRING_TO_HASH;
    if(strlen(tmp) == 0)
        return;

    for(; *tmp != '\0'; ++tmp)
        value = (unsigned short)*tmp + 31 * value;   
    
    _snprintf(buf, sizeof(buf), "%s", STRING_TO_HASH);
    printf("%s : 0x%x\n", buf, value);

}

int __cdecl main(int argc, char* argv[], char* envp[]) 
{
    Lab4a();
    return 0;
}