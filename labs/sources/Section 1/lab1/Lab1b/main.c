#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

int __declspec(dllexport) Lab1b(int a)
{
	int i = 0;
	for(; i < a; ++i)
		printf("%c\n", (char)((rand() & 0xff) % 0x5a));
	
	return a;

}

int __cdecl main(int argc, char** argv, char** envp)
{
	int a;
	srand(GetTickCount());

	a = rand() & 0xfff;

	printf("%d\n", Lab1b(a));

	return 0;
}