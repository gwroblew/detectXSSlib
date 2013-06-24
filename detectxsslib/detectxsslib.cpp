#include "detectxsslib.h"

#define	TC(disp,str)	(*(unsigned short *)(p + disp) == str)		// compare two characters
#define	FC(disp,str)	(*(unsigned long *)(p + disp) == str)		// compare four characters

void xsslibUrlInit(xsslibUrl *url)
{
	memset(url->Url, 0, sizeof(url->Url));
	url->Result = XssUnknown;
};

void xsslibUrlSetUrl(xsslibUrl *url, char *src)
{
	char *dst = url->Url;

	memset(url->Url, 0, sizeof(url->Url));

	while(*src != 0)
		*dst++ = *src++;

	*dst = 0;
}

XSSRESULT xsslibUrlScan(xsslibUrl *url)
{
	char c, *p = url->Url;
	int st1 = 0, st2 = 0, st3 = 0, st4 = 0;
	int rule = 0;

	while((c = *p++) != 0)
	{
		// match <script.*?>
		//
		switch(st1)
		{
		case 0:
			if(c == '<' && FC(0,'scri') && TC(4,'pt'))
				st1 = st3 = 1;
			break;
		case 1:
			if(c == '>')
			{
				rule = 1;
				goto xssFound;
			}
			break;
		}
		// match <style.*?>
		//
		switch(st2)
		{
		case 0:
			if(c == '<' && FC(0,'styl') && *(p + 4) == 'e')
				st2 = 1;
			break;
		case 1:
			if(c == '>')
			{
				rule = 2;
				goto xssFound;
			}
			break;
		}
		// match <script.*?[ /+\t]*?((src)|(xlink:href)|(href))[ /+\t]*=
		//
		switch(st3)
		{
		case 0:
			if(st1 > 0 && (c == '<' && FC(0,'scri') && TC(4,'pt')))
				st3 = 1;
			break;
		case 1:
			if(c == ' ' || c == '/' || c == '+' || c == 9)
				st3 = 2;
			else if((c == 's' && TC(2,'rc')) || (c == 'x' && FC(0,'xlin') && FC(4,'k:hr') && TC(8,'ef')) || (FC(-1,'href')))
				st3 = 3;
			break;
		case 2:
			if((c == 's' && TC(2,'rc')) || (c == 'x' && FC(0,'xlin') && FC(4,'k:hr') && TC(8,'ef')) || (FC(-1,'href')))
				st3 = 3;
			else if(!(c == ' ' || c == '/' || c == '+' || c == 9))
				st3 = 0;
			break;
		case 3:
			if(c == ' ' || c == '/' || c == '+' || c == 9)
				st3 = 4;
			else if(c == '=')
			{
				rule = 3;
				goto xssFound;
			}
			break;
		case 4:
			if(c == '=')
			{
				rule = 3;
				goto xssFound;
			}
			else if(!(c == ' ' || c == '/' || c == '+' || c == 9))
				st3 = 0;
			break;
		}
		// match <[i]?frame.*?[ /+\t]*?src[ /+\t]*=
		//
		switch(st4)
		{
		}
	}

	url->Result = XssClean;
	return url->Result;

xssFound:
	url->Result = XssFound;

	return url->Result;
}
