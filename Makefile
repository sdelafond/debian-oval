# If this makefile is not generic enough to support a translation,
# please contact debian-www.

WMLBASE=../..
CUR_DIR=security/oval
SUBS=

PYTHON=/usr/bin/python

include $(WMLBASE)/Make.lang

XMLFILES=$(shell for release in wheezy jessie stretch; do echo oval-definitions-$$release.xml; done)

XMLDESTFILES=$(patsubst %,$(HTMLDIR)/%,$(XMLFILES))

all:: check_empty_files $(XMLFILES)

install:: $(XMLDESTFILES)

oval-definitions-%.xml: force
	@[ -e $(PYTHON) ] || { echo "ERROR: Required python binary $(PYTHON) is not available, aborting generation" >&2; exit 1; }
	-$(PYTHON) generate.py -d .. -r $(patsubst oval-definitions-%.xml,%,$@) >$@
# Warn if empty files are generated
# Note: They cannot be removed or the install target will fail later
	@[ -s $@ ] || echo "WARNING: OVAL Definition $@ is empty, please review script and/or DSAs" 

$(XMLDESTFILES): $(HTMLDIR)/%: %
	@test -d $(HTMLDIR) || mkdir -m g+w -p $(HTMLDIR)
	install -m 664 -p $< $(HTMLDIR)

# TODO 'clean' could also remove the python-compiled files generated
# by Python when running the script
clean::
	  -rm -f oval-definitions-*.xml
	
cleandest::
	  -rm -f $(HTMLDIR)/oval-definitions-*.xml
	
# Remove empty files to force regeneration
check_empty_files:
	@for file in oval-definitions-*.xml; do \
		if [ -e "$$file" -a ! -s "$$file" ] ; then \
			rm $$file ; \
		fi \
	done

force:
.PHONY : check_empty_files force
