# This Makefile should need no changes from webwml/english/security/oval/Makefile
# Please send a message to debian-www if you need to modify anything
# so the problem can be fixed.

WMLBASE=../..
CUR_DIR=security/oval
SUBS=

# We need this python version, 2.3 will not do
PYTHON=/usr/bin/python2.4

include $(WMLBASE)/Make.lang

genxml: $(PYTHON)
	 @for year in `seq 2000 2008`; do \
		 [ -d "../$$year" ] && \
	 	$(PYTHON) parseDsa2Oval.py -d ../$$year >oval-definitions-$$year.xml;  \
	 done

# TODO 'clean' could also remove the python-compiled files generated
# by Python when running the script
clean::
	  -rm -f oval-definitions*.xml
