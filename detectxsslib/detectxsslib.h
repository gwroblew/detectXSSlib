#ifndef __DETECTXSSLIB_H
#define	__DETECTXSSLIB_H

#include <memory.h>

#define	MAX_URL_LENGTH	(4096)
#define	MAX_TOKENS		(4096)

typedef enum { XssUnknown, XssClean, XssSuspected, XssFound } XSSRESULT;

typedef struct _xsslibUrl
{
	char		Url[MAX_URL_LENGTH + 64];		// for skipping length checks in regexes
	char		Tokens[MAX_TOKENS];
	XSSRESULT	Result;
	int			TokenCnt;
	int			MatchedRule;
} xsslibUrl;

void xsslibUrlInit(xsslibUrl *url);
void xsslibUrlSetUrl(xsslibUrl *url, char *x);
XSSRESULT xsslibUrlScan(xsslibUrl *url);

#endif // !__DETECTXSSLIB_H
