// xssscan.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include "detectxsslib.h"

int main(int argc, char* argv[])
{
	xsslibUrl url;
	char line[MAX_URL_LENGTH + 1];

	line[MAX_URL_LENGTH] = 0;

	xsslibUrlInit(&url);

	FILE *fr = fopen(argv[1], "rb");

	while(fgets(line, MAX_URL_LENGTH, fr) != NULL)
	{
		xsslibUrlSetUrl(&url, line);

		if(xsslibUrlScan(&url) == XssFound)
		{
			printf("%s\n", line);
		}
	}

	fclose(fr);

	//for(int i = 0; i < url.TokenCnt; i++)
	//	printf("%d\n", url.Tokens[i]);

	return 0;
}
