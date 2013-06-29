This folder contains test files to use with xssscan tool to test the XSS scanning library. To protect vulnerable websites, all domain names in the data sets were replaced with www.example.com.

testset1.txt - over 30,000 URLs with duplicate hosts and paths, coming from a large data set and selected for higher probability of having XSS attack.

attacks.txt - about 1,400 URLs with confirmed and reproduced XSS attacks of different form; all entries in this set should be detected by detectxsslib filter.

todo.txt - an attack sample that is not detected yet by detectxsslib; it requires implementing a parsing of obfuscated form of "javascript:" string.
