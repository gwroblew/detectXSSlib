This is a simple proof-of-concept module for integrating detectxsslib into nginx server. The module detects XSS attacks and logs them into the error log file (there is no blocking option).

To compile follow default nginx compilation procedure with:

./configure --add-module=detectxsslib/modules/nginx/detectxsslib

Make sure that the configuration script added the module to the ngx_modules.c file (if not, add it there manually).
