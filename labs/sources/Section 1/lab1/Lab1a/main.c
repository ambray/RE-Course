#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

int __declspec(dllexport) Lab1a(int a, int b)
{
	return a + b;
}

int __cdecl main(int argc, char** argv, char** envp)
{
	int a, b;
	srand(GetTickCount());

	a = rand() & 0xfff;
	b = rand() & 0xff;

	printf("%d\n", Lab1a(a,b));

	return 0;
}