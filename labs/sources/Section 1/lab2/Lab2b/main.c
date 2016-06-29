#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

static WORD get_attrib(char in)
{
    WORD out = 0;
    switch(in) {
    case 'a':
        out = 0x10;
        break;
    case 'b':
        out = 0x20;
        break;
    case 'c':
        out = 0x40;
        break;
    case 'd':
        out = 0x10 | 0x20;
        break;
    case 'A':
        out = 0x10 | 0x40;
        break;
    case 'B':
        out = 0x20 | 0x40;
        break;
    case 'Z':
        out = 0x10 | 0x20 | 0x40;
        break;
    case 'm':
        out = 0x10 | 0x01;
        break;
    case 's':
        out = 0x20 | 0x01;
        break;
    case 'C':
        out = 0x40 | 0x02;
        break;
    case 'x':
        out = 0x10 | 0x20 | 0x04;
        break;
    case 'F':
        out = 0x10 | 0x40 | 0x01;
        break;
    case 'r':
        out = 0x20 | 0x40 | 0x02;
        break;
    case 'l':
        out = 0x10 | 0x20 | 0x40 | 0x04 | 0x02 | 0x04;
        break;
    default:
        out = 0;
    }

    return out;
}

static BOOL set_cons(WORD value)
{
    HANDLE hStdo = GetStdHandle(STD_OUTPUT_HANDLE);

    return SetConsoleTextAttribute(hStdo, value | BACKGROUND_INTENSITY);

}

BOOL __declspec(dllexport) __cdecl Lab2b(void)
{
    char value = 0x00;
    WORD outval = 0;

    for(;; outval = 0) {
        printf("Enter Thing:\n");
        fscanf(stdin, "%c", &value);

        outval = get_attrib(value);
        if(!set_cons(outval))
            break;
    }

    return TRUE;
}

int __cdecl main(int argc, char* argv[], char* envp[]) 
{

    Lab2b();
    return 0;
}