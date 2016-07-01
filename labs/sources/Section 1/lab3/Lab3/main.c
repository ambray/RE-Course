#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define LB_UPPER		0x41
#define UB_UPPER		0x5a

#define LB_LOWER		0x61
#define UB_LOWER		0x7a

char rotate(char x)
{
	int basis = 0;

	if(x <= UB_UPPER && x >= LB_UPPER) {
		basis = LB_UPPER;
	} else if(x <= UB_LOWER && x >= LB_LOWER) {
		basis = LB_LOWER;
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
	//char* init = "This is indeed the key. You have found clearly found it, and succeeded at this challenge.";
	char* init = "Guvf vf vaqrrq gur xrl. Lbh unir sbhaq pyrneyl sbhaq vg, naq fhpprrqrq ng guvf punyyratr.";
	char* first = "Qrpbqr zr";

	if(NULL == (tmp = (char*)r13(first, strlen(first)))) {
		printf("Failed!\n");
		return;
	}

	printf("%s: %s\n", tmp, init);

	free(tmp);
}

int __cdecl main(int argc, char** argv, char** envp)
{
	Lab3a();
	return 0;
}