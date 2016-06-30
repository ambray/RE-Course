#include <Windows.h>
#include <stdio.h>


int __cdecl main(int argc, char** argv, char** envp)
{
	size_t token = 0;
	__debugbreak();


	if(0 == (token & 1))
		return -1;

	if(0 == (token & 8))
		return -2;

	MessageBoxA(NULL, "[*] Success!", "Success!", MB_OK);

	return 0;
}