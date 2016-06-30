#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define LOWER_BOUND_UC		0x41
#define UPPER_BOUND_UC		0x5a

#define LOWER_BOUND_LC		0x61
#define UPPER_BOUND_LC		0x7a

char rotate(char x)
{
	int basis = 0;

	if(x <= 0x5a && x >= 0x41) {
		basis = 0x41;
	} else if(x <= 0x7a && x >= 0x61) {
		basis = 0x61;
	} else {
		return x;
	}
	
	return (((x - basis) + 13) % 26) + basis;
}

char* r13(char* buf, size_t size)
{
	char* tmp = NULL;
	int i = 0;

	if(NULL == buf)
		return NULL;

	if(NULL == (tmp = (char*)malloc(size + 1))) {
		printf("[x] Out of memory!\n");
		return NULL;
	}

	memset(tmp, 0x00, size+1);

	for(; buf[i] != '\0'; ++i) {
		tmp[i] = rotate(buf[i]);
	}


	return tmp;
}

void __declspec(dllexport) __cdecl Lab3a()
{
	char* tmp = NULL;
	char* tmp2 = NULL;
	char* init = "This is a test string.";

	if(NULL == (tmp = (char*)r13(init, strlen(init)))) {
		printf("Failed!\n");
		return;
	}

	printf("%s\n", tmp);

	free(tmp);
}

int __cdecl main(int argc, char** argv, char** envp)
{
	Lab3a();
	return 0;
}