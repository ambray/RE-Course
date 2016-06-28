#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

uint32_t hash_func(char* msg)
{
	uint32_t value = 0;
	int counter = 0;

	if (NULL == msg)
		return value;

	for (counter = 0; *(msg + counter) != '\0'; ++counter)
		value = (short)*(msg + counter) + 31 * value;

	return value;
}


int main(int argc, char** argv, char** envp)
{
	char buf[MAX_PATH + 1];
	size_t bufIndex = 0;
	uint32_t hashedVal = 0;
	int i = 0;

	memset(buf, 0, sizeof(buf));

	for (i = 0; bufIndex < MAX_PATH && i < argc; ++i) {
		size_t current = 0;
		if (NULL != argv[i] && '\0' != *(argv[i])) {
			current = strlen(argv[i]);
			if (current >= MAX_PATH - bufIndex)
				continue;

			memcpy((buf + bufIndex), argv[i], current);
			bufIndex += current;
			*(buf + bufIndex) = (char)0x20;
			++bufIndex;
		}
	}

	*(buf + bufIndex - 1) = '\0';

	if (0 == (hashedVal = hash_func(buf)))
		return -1;

	printf("%s, 0x%x\n", buf, hashedVal);

	return 0;
}