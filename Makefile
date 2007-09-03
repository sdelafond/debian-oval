# This Makefile should need no changes from webwml/english/security/oval/Makefile
# Please send a message to debian-www if you need to modify anything
# so the problem can be fixed.

WMLBASE=../..
CUR_DIR=security/oval
SUBS=

# We need this python version, 2.3 will not do
PYTHON=/usr/bin/python2.4

include $(WMLBASE)/Make.lang

# NOTE: CUR_YEAR is defined in $(WMLBASE)/Makefile.common
#CUR_YEAR=$(shell date +%Y)
XMLFILES=$(shell for year in `seq 2000 $(CUR_YEAR)`; do echo oval-definition-$$year.xml; done)

XMLDESTFILES=$(patsubst %,$(HTMLDIR)/%,$(XMLFILES))

all:: $(XMLFILES)

install:: $(XMLDESTFILES)

oval-definition-%.xml: $(PYTHON) parseDsa2Oval.py \
	$(wildcard $(ENGLISHDIR)/security/%/dsa-*.wml)  \
	$(wildcard $(ENGLISHDIR)/security/%/dsa-*.data) 
	$(PYTHON) parseDsa2Oval.py -d ../$(patsubst oval-definition-%.xml,%,$@) >$@

$(XMLDESTFILES): $(HTMLDIR)/%: %
	@test -d $(HTMLDIR) || mkdir -m g+w -p $(HTMLDIR)
	install -m 664 -p $< $(HTMLDIR)

# TODO 'clean' could also remove the python-compiled files generated
# by Python when running the script
clean::
	  -rm -f oval-definitions-*.xml
	
cleandest::
	  -rm -f $(HTMLDIR)/oval-definitions-*.xml
