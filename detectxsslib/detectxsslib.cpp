#include "detectxsslib.h"

#define SWAP_UINT16(x) (((x) >> 8) | ((x) << 8))
#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))

#define	TC(disp,str)	(*(unsigned short *)(p + disp) == SWAP_UINT16(str))		// compare two characters
#define	FC(disp,str)	(*(unsigned long *)(p + disp) == SWAP_UINT32(str))		// compare four characters

void xsslibUrlInit(xsslibUrl *url)
{
	memset(url->Url, 0, sizeof(url->Url));
	url->Result = XssUnknown;
};

#define	TOKEN_SCRIPT			1	// <script
#define	TOKEN_STYLE				2	// <style
#define TOKEN_SRC				3	// src
#define TOKEN_XLINKHREF			4	// xlink:href
#define	TOKEN_HREF				5	// href
#define	TOKEN_EQ				6	// =
#define	TOKEN_XTAB				7	// [ /+\t]*
#define	TOKEN_FRAME				8	// <frame
#define	TOKEN_IFRAME			9	// <iframe
#define	TOKEN_VMLFRAME			10	// vmlframe
#define	TOKEN_EMBED				11	// <embed
#define	TOKEN_IMPORT			12	// <import <?import
#define	TOKEN_IMPLEMENTATION	14	// <implementation
#define	TOKEN_LINK				15	// <link
#define	TOKEN_BASE				16	// <base
#define	TOKEN_APPLET			17	// <applet
#define	TOKEN_OBJECT			18	// <object
#define	TOKEN_META				19	// <meta
#define	TOKEN_HTTPEQUIV			20	// http-equiv
#define	TOKEN_CHARSET			21	// charset
#define	TOKEN_TYPE				22	// type
#define	TOKEN_CODETYPE			23	// codetype
#define	TOKEN_CLASSID			24	// classid
#define	TOKEN_CODE				25	// code
#define	TOKEN_DATA				26	// data
#define	TOKEN_LT				27	// <
#define	TOKEN_GT				28	// >
#define	TOKEN_JAVASCRIPT		29	// javascript:
#define	TOKEN_VBSCRIPT			30	// vbscript:
#define	TOKEN_ANY				127	// .*

#define	TOKEN(x,l)	{ if(p != last_match) { url->Tokens[ti++] = TOKEN_ANY; } url->Tokens[ti++] = TOKEN_##x; p += l; last_match = p; continue; }

inline char xsslibToLower(char c)
{
	if(c >= 'A' && c <= 'Z')
		return c + 32;

	return c;
}

inline int xsslibHexValue(char c)
{
	if(c >= 'a')
		return c - 'a' + 10;

	return c - '0';
}

void xsslibUrlSetUrl(xsslibUrl *url, char *src)
{
	char *dst = url->Url;

	while(*src != 0)
		*dst++ = xsslibToLower(*src++);

	memset(dst, 0, 64);

	char c, *p = url->Url;
	int st = 0;
	int ti = 0;
	char *last_match = p;

	if(FC(0,'http'))
	{
		p += 4;

		if(*p == 's')
			p++;

		if(TC(0,'//'))
			p += 2;
	}

	while((c = *p++) != 0)
	{
		if(c == '%')
		{
			c = (xsslibHexValue(*p++) << 4) + xsslibHexValue(*p);
			*p++ = c;
		}

		switch(st)
		{
		case 0:
			switch(c)
			{
			case '<':
				st = 1;
				continue;
			case '>':
				TOKEN(GT,0);
			case '=':
				TOKEN(EQ,0);
			case ' ':
			case '/':
			case '+':
			case 9:
				st = 2;
				continue;
			case 's':
				if(TC(0,'rc'))
					TOKEN(SRC,2);
				break;
			case 'c':
				if(FC(-1,'code'))
				{
					if(FC(3,'type'))
						TOKEN(CODETYPE,7);

					TOKEN(CODE,3);
				}
				if(FC(0,'hars') && TC(4,'et'))
					TOKEN(CHARSET,6);
				if(FC(0,'lass') && TC(4,'id'))
					TOKEN(CLASSID,6);
				break;
			case 'd':
				if(FC(-1,'data'))
					TOKEN(DATA,3);
				break;
			case 'h':
				if(FC(-1,'href'))
					TOKEN(HREF,3);
				if(FC(0,'ttp-') && FC(4,'equi') && *(p + 8) == 'v')
					TOKEN(HTTPEQUIV,9);
				break;
			case 'j':
				if(FC(0,'avas') && FC(4,'crip') && TC(8,'t:'))
					TOKEN(JAVASCRIPT,10);
				break;
			case 't':
				if(FC(-1,'type'))
					TOKEN(TYPE,3);
				break;
			case 'v':
				if(FC(0,'mlfr') && TC(4,'am') && *(p + 6) == 'e')
					TOKEN(VMLFRAME,7);
				if(FC(0,'bscr') && FC(4,'ipt:'))
					TOKEN(VBSCRIPT,8);
				break;
			case 'x':
				if(FC(0,'link') && FC(4,':hre') && *(p + 8) == 'f')
					TOKEN(XLINKHREF,9);
				break;
			}
			break;
		case 1:
			st = 0;
			switch(c)
			{
			case '?':
				if(FC(0,'impo') && TC(4,'rt'))
					TOKEN(IMPORT,6);
				break;
			case 'a':
				if(FC(0,'pple') && *(p + 4) == 't')
					TOKEN(APPLET,5);
				break;
			case 'b':
				if(FC(-1,'base'))
					TOKEN(BASE,3);
				break;
			case 'e':
				if(FC(0,'mbed'))
					TOKEN(EMBED,4);
				break;
			case 'f':
				if(FC(0,'rame'))
					TOKEN(FRAME,4);
				break;
			case 'i':
				if(FC(0,'fram') && *(p + 4) == 'e')
					TOKEN(IFRAME,5);
				if(FC(0,'mple') && FC(4,'ment') && FC(8,'atio') && *(p + 12) == 'n')
					TOKEN(IMPLEMENTATION,13);
				if(FC(0,'mpor') && *(p + 4) == 't')
					TOKEN(IMPORT,5);
				break;
			case 'l':
				if(FC(-1,'link'))
					TOKEN(LINK,3);
				break;
			case 'm':
				if(FC(-1,'meta'))
					TOKEN(META,3);
				break;
			case 'o':
				if(FC(0,'bjec') && *(p + 4) == 't')
					TOKEN(OBJECT,5);
				break;
			case 's':
				if(FC(0,'crip') && *(p + 4) == 't')
					TOKEN(SCRIPT,5);
				if(FC(0,'tyle'))
					TOKEN(STYLE,4);
				break;
			}
			TOKEN(LT,-1);
			break;
		case 2:
			switch(c)
			{
			case ' ':
			case '/':
			case '+':
			case 9:
				continue;
			}
			st = 0;
			TOKEN(XTAB,-1);
			break;
		}
	}

	url->TokenCnt = ti;
}

#define	RULE(n)				{ rule = n; goto xssFound; }
#define	MATCH(t)			{ while(i < url->TokenCnt) if(url->Tokens[i++] == t) break; }
#define	MATCH2(t1,t2)		{ while(i < url->TokenCnt) { if(url->Tokens[i] == t1 || url->Tokens[i] == t2) { i++; break; } i++; } }
#define	MATCH3(t1,t2,t3)	{ while(i < url->TokenCnt) { if(url->Tokens[i] == t1 || url->Tokens[i] == t2 || url->Tokens[i] == t3) { i++; break; } i++; } }
#define	MATCH5(t1,t2,t3,t4,t5)	{ while(i < url->TokenCnt) { if(url->Tokens[i] == t1 || url->Tokens[i] == t2 || url->Tokens[i] == t3 || url->Tokens[i] == t4 || url->Tokens[i] == t5) { i++; break; } i++; } }
#define	MATCHEND(t,r)		{ while(i < url->TokenCnt) if(url->Tokens[i++] == t) RULE(r); }
#define	IFNEXT(t)			if(url->Tokens[i] == t) { i++;
#define	ENDIF				}
#define	IFNEXTEND(t,r)		if(url->Tokens[i] == t) RULE(r);

XSSRESULT xsslibUrlScan(xsslibUrl *url)
{
	int rule = 0;
	int i = 0;

	// rule 1: match <script.*?>
	//
	i = 0;
	MATCH(TOKEN_SCRIPT);
	MATCHEND(TOKEN_GT,1);

	// rule 2: match <style.*?>
	//
	i = 0;
	MATCH(TOKEN_STYLE);
	MATCHEND(TOKEN_GT,2);

	// rule 3: match <script.*?[ /+\t]*?((src)|(xlink:href)|(href))[ /+\t]*=
	//
	i = 0;
	MATCH(TOKEN_SCRIPT);
	MATCH3(TOKEN_SRC,TOKEN_XLINKHREF,TOKEN_HREF);
	IFNEXTEND(TOKEN_EQ,3);
	IFNEXT(TOKEN_XTAB);
		IFNEXTEND(TOKEN_EQ,3);
	ENDIF

	// rule 4: match <[i]?frame.*?[ /+\t]*?src[ /+\t]*=
	//
	i = 0;
	MATCH2(TOKEN_FRAME,TOKEN_IFRAME);
	MATCH(TOKEN_SRC);
	IFNEXTEND(TOKEN_EQ,4);
	IFNEXT(TOKEN_XTAB);
		IFNEXTEND(TOKEN_EQ,4);
	ENDIF

	// rule 5: match <.*[:]vmlframe.*?[ /+\t]*?src[ /+\t]*=
	//
	i = 0;
	MATCH(TOKEN_LT);
	MATCH(TOKEN_VMLFRAME);
	MATCH(TOKEN_SRC);
	IFNEXTEND(TOKEN_EQ,5);
	IFNEXT(TOKEN_XTAB);
		IFNEXTEND(TOKEN_EQ,5);
	ENDIF

	// rule 6: match javascript:.*?
	//
	i = 0;
	MATCHEND(TOKEN_JAVASCRIPT,6);

	// rule 7: match vbscript:.*?
	//
	i = 0;
	MATCHEND(TOKEN_VBSCRIPT,7);

	// rule 8: match <EMBED[ /+\t].*?((src)|(type)).*?=
	//
	i = 0;
	MATCH(TOKEN_EMBED);
	IFNEXT(TOKEN_XTAB)
		MATCH2(TOKEN_SRC,TOKEN_TYPE);
		MATCHEND(TOKEN_EQ,8);
	ENDIF

	// rule 9: match <[?]?import[ /+\t].*?implementation[ /+\t]*=
	//
	i = 0;
	MATCH(TOKEN_IMPORT);
	IFNEXT(TOKEN_XTAB)
		MATCH(TOKEN_IMPLEMENTATION);
		IFNEXTEND(TOKEN_EQ,9);
		IFNEXT(TOKEN_XTAB);
			IFNEXTEND(TOKEN_EQ,9);
		ENDIF
	ENDIF

	// rule 10: match <META[ /+\t].*?http-equiv[ /+\t]*=[ /+\t]*[\"\'`]?(((c|(&#x?0*((67)|(43)|(99)|(63));?)))|((r|(&#x?0*((82)|(52)|(114)|(72));?)))|((s|(&#x?0*((83)|(53)|(115)|(73));?))))
	//
	i = 0;
	MATCH(TOKEN_META);
	IFNEXT(TOKEN_XTAB)
		MATCH(TOKEN_HTTPEQUIV);
		IFNEXTEND(TOKEN_EQ,10);
		IFNEXT(TOKEN_XTAB);
			IFNEXTEND(TOKEN_EQ,10);
		ENDIF
	ENDIF

	// rule 11: match <META[ /+\t].*?charset[ /+\t]*=
	//
	i = 0;
	MATCH(TOKEN_META);
	IFNEXT(TOKEN_XTAB)
		MATCH(TOKEN_CHARSET);
		IFNEXTEND(TOKEN_EQ,11);
		IFNEXT(TOKEN_XTAB);
			IFNEXTEND(TOKEN_EQ,11);
		ENDIF
	ENDIF

	// rule 12: match <LINK[ /+\t].*?href[ /+\t]*=
	//
	i = 0;
	MATCH(TOKEN_LINK);
	IFNEXT(TOKEN_XTAB)
		MATCH(TOKEN_HREF);
		IFNEXTEND(TOKEN_EQ,12);
		IFNEXT(TOKEN_XTAB);
			IFNEXTEND(TOKEN_EQ,12);
		ENDIF
	ENDIF

	// rule 13: match <BASE[ /+\t].*?href[ /+\t]*=
	//
	i = 0;
	MATCH(TOKEN_BASE);
	IFNEXT(TOKEN_XTAB)
		MATCH(TOKEN_HREF);
		IFNEXTEND(TOKEN_EQ,13);
		IFNEXT(TOKEN_XTAB);
			IFNEXTEND(TOKEN_EQ,13);
		ENDIF
	ENDIF

	// rule 14: match <APPLET[ /+\t>]
	//
	i = 0;
	MATCH(TOKEN_APPLET);
	IFNEXTEND(TOKEN_XTAB,14);
	IFNEXTEND(TOKEN_GT,14);

	// rule 15: match <OBJECT[ /+\t].*?((type)|(codetype)|(classid)|(code)|(data))[ /+\t]*=
	//
	i = 0;
	MATCH(TOKEN_OBJECT);
	IFNEXT(TOKEN_XTAB)
		MATCH5(TOKEN_TYPE,TOKEN_CODETYPE,TOKEN_CLASSID,TOKEN_CODE,TOKEN_DATA);
		IFNEXTEND(TOKEN_EQ,15);
		IFNEXT(TOKEN_XTAB);
			IFNEXTEND(TOKEN_EQ,15);
		ENDIF
	ENDIF

	url->Result = XssClean;
	return url->Result;

xssFound:
	url->Result = XssFound;
	url->MatchedRule = rule;

	return url->Result;
}
