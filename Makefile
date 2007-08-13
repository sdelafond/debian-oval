# This Makefile should need no changes from webwml/english/security/oval/Makefile
# Please send a message to debian-www if you need to modify anything
# so the problem can be fixed.

WMLBASE=../..
CUR_DIR=security/oval
SUBS=

PYTHON=/usr/bin/python2.4

include $(WMLBASE)/Make.lang

genxml: $(PYTHON)
	 @for year in `seq 2000 2008`; do \
		 [ -d "../$$year" ] && \
	 	$(PYTHON) parseDsa2Oval.py -d ../$$year >oval-definitions-$$year.xml;  \
	 done

clean::
	  -rm -f oval-definitions*.xml
