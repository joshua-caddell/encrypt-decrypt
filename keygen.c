#include<stdlib.h>
#include<stdio.h>

int main(int argc, char *argv[])
{	
	srand(time(NULL));

	int i, len = atoi(argv[1]);
	char key[len + 1]; // +1 allows for the newline

	for(i = 0; i < len; i++)
	{
		int num = rand() % 27;
		num += 65;

		if(num == 91)
			num = 32;
		key[i] = num;	
	}
	
	key[len] = '\0';
	
	printf("%s\n", key);

	return 0;
}
