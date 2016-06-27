#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define BUFFER_SIZE 512
char buffer[BUFFER_SIZE];
//char magicStr[] = "Hey dev, Without you my world is NULL.";
char magicStr[] = "bOS\nNO\\\x06\n}C^BE_^\nSE_\nGS\n]EXFN\nCY\nd\x7f\x66\x66\x04"; //xor with 42
#define XOR_KEY 42

HANDLE openFile(LPCTSTR filename) {
    return CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

void deoffuscate(char* buffer, int size) {
    int magicSize = 0;
    int i;
    if (magicSize > size) {
        printf("Your heart is too small.\n");
        return;
    }

    memset(buffer, 0, size);

    magicSize = strlen(magicStr);
    for (i = 0; i < magicSize; ++i) {
        buffer[i] = magicStr[i] ^ 42;
    }
}

int __cdecl main(int argc, char* argv[]) {

    HANDLE hFile = openFile("C:\\badlove.dat");
    DWORD bytesRead = 0;
    DWORD err = 0;
    char magic[BUFFER_SIZE] = { 0 };

    memset(buffer, 0, BUFFER_SIZE);

    if (hFile == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        printf("My love is lost\n");
        exit(0);
    }

    if (!ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
        printf("I can't read your love\n");
        exit(0);
    }

    deoffuscate(magic, BUFFER_SIZE);
    if (strstr(buffer, magic)) {
        printf("You have a const pointer to my microprocessor.\n");
        printf("Congrats... your done!\n");
    }
    else {
        printf("What is? %s\n", buffer);
    }
    
    return 0;
}