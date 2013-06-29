//----------------------------------------------------------------------------------------
// THIS CODE AND INFORMATION IS PROVIDED "AS-IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Greg Wroblewski. All rights reserved.
//----------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <map>
#include "detectxsslib.h"

std::string g_url;
std::string g_file;
bool g_filemode = false;
bool g_replacehost = false;
bool g_deduplicate = false;
bool g_showrule = false;
bool g_showtokens = false;
bool g_listxss = true;

typedef struct
{
	std::string path;
	int			rule;
} XSSFIND;

void parseargs(int argc, char *argv[])
{
#ifdef __GNUC__
	if(argc == 1 || strcasecmp(argv[1], "-h") == 0)
#else
	if(argc == 1 || _stricmp(argv[1], "-h") == 0)
#endif
	{
		printf("\n");
		printf("xssscan ver 1.0 (c) 2013 Greg Wroblewski\n");
		printf("\n");
		printf("Command line tool for detection of XSS attacks in URLs. Based on ModSecurity rules from OWASP CRS.\n");
		printf("Optimized for performance and large scale data mining.\n");
		printf("\n");
		printf("Usage:\n");
		printf("xssscan [-t] [-r] [-x] <URL>\n");
		printf("xssscan [-a] [-d] [-r] [-x] -f <TEXT_FILE_WITH_URLS>\n");
		printf("\n");
		printf("Options:\n");
		printf(" -a - in output replace host names with www.example.com\n");
		printf(" -d - deduplicate URLs by same host name\n");
		printf(" -r - show rule number for detected XSS (for statistics or debugging)\n");
		printf(" -t - show tokens of parsed URL (useful for debugging only)\n");
		printf(" -x - list only URLs where XSS was not detected (default: was detected)\n");
		printf("\n");
		exit(0);
	}

	char *last = argv[argc - 1];

	for(int i = 1; i < argc - 1; i++)
	{
		if(strlen(argv[i]) < 2 || argv[i][0] != '-')
			continue;

		switch(argv[i][1])
		{
		case 'a':
			g_replacehost = true;
			break;
		case 'd':
			g_deduplicate = true;
			break;
		case 'r':
			g_showrule = true;
			break;
		case 't':
			g_showtokens = true;
			break;
		case 'x':
			g_listxss = false;
			break;
		case 'f':
			g_filemode = true;
			break;
		}
	}

	if(g_filemode)
		g_file = last;
	else
		g_url = last;
}

int main(int argc, char* argv[])
{
	xsslibUrl url;
	char line[MAX_URL_LENGTH + 1];

	line[MAX_URL_LENGTH] = 0;

	parseargs(argc, argv);

	xsslibUrlInit(&url);

	if(!g_filemode)
	{
		xsslibUrlSetUrl(&url, (char *)g_url.data());

		if(g_showtokens)
		{
			printf("URL tokens:\n");

			for(int i = 0; i < url.TokenCnt; i++)
				printf("%d\n", url.Tokens[i]);
		}

		bool result = xsslibUrlScan(&url) == XssFound;

		if((result && g_listxss) || (!result && !g_listxss))
		{
			if(g_showrule)
				printf("%d ", url.MatchedRule);

			printf("%s\n", g_url.data());
		}
		return 0;
	}

	FILE *fr = fopen(g_file.data(), "rb");
	std::map<std::string,XSSFIND> urlmap;

	if(fr == NULL)
	{
		printf("Cannot open file %s!\n\n", g_file.data());
		exit(-1);
	}

	while(fgets(line, MAX_URL_LENGTH, fr) != NULL)
	{
		int l = strlen(line);

		while(--l >= 0)
			if(line[l] == 10 || line[l] == 13)
				line[l] = 0;

		xsslibUrlSetUrl(&url, line);

		bool result = xsslibUrlScan(&url) == XssFound;

		if((result && g_listxss) || (!result && !g_listxss))
		{
			char *p = line;
			int sc = 0;

			while(*p != 0)
				if(*p++ == '/' && ++sc == 3)
					break;

			if(g_deduplicate)
			{
				std::string tmpurl = p;
				*p = 0;
				std::string host = line;

				if(urlmap.find(host) == urlmap.end())
				{
					XSSFIND xf;

					xf.path = tmpurl;
					xf.rule = url.MatchedRule;

					urlmap[host] = xf;
				}
			}
			else
			{
				if(g_showrule)
					printf("%d ", url.MatchedRule);

				if(g_replacehost)
					printf("http://www.example.com/%s\n", p);
				else
					printf("%s\n", line);
			}
		}
	}

	fclose(fr);

	if(g_deduplicate)
	{
		for(std::map<std::string,XSSFIND>::iterator it = urlmap.begin(); it != urlmap.end(); ++it)
		{
			if(g_showrule)
				printf("%d ", it->second.rule);

			if(g_replacehost)
				printf("http://www.example.com/%s\n", it->second.path.data());
			else
				printf("%s%s\n", it->first.data(), it->second.path.data());
		}
	}

	return 0;
}
