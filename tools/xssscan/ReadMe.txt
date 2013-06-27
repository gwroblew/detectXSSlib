========================================================================
  CONSOLE APPLICATION : xssscan
========================================================================

xssscan ver 1.0 (c) 2013 Greg Wroblewski

Command line tool for detection of XSS attacks in URLs. Based on ModSecurity rules from OWASP CRS.
Optimized for performance and large scale data mining.

Usage:
xssscan [-t] [-r] [-x] <URL>
xssscan [-a] [-d] [-r] [-x] -f <TEXT_FILE_WITH_URLS>

Options:
	-a - in output replace host names with www.example.com
	-d - deduplicate URLs by same host name
	-r - show rule number for detected XSS (for statistics or debugging)
	-t - show tokens of parsed URL (useful for debugging only)
	-x - list only URLs where XSS was not detected (default: was detected)
