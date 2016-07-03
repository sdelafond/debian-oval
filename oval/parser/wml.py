# -*- coding: utf-8 -*-
# oval.parser.wml - module to parse descriptions of 
# Debian Security Advisories stored in wml format.
# Extrected tags:
# 	<description>
#		<moreinfo>- Paragraphs before descriptions of
# each release status
#
# (c) 2007 Pavel Vinogradov   
# (c) 2004 Javier Fernandez-Sanguino                                                                                                    
# Licensed under the GNU General Public License version 2.

import re
import os
import sys
import logging

# Format of wml files is:
#<define-tag description>DESCRIPTION</define-tag>
#<define-tag moreinfo>Multiline information</define-tag>
def parseFile (path):
	""" Parse wml file with description of Debian Security Advisories 
	
	Keyword arguments:
	path -- full path to wml file
	
	return list (dsa id, tags data)"""
	
	data = {}
	moreinfo = False
	
	filename = os.path.basename (path)
	
	patern = re.compile(r'dsa-(\d+)')
	result = patern.search(filename)
	if result:
		dsa = result.groups()[0]
	else:
		logging.log(logging.WARNING, "File %s does not look like a proper DSA wml description, not checking" % filename)
		return (None)
	
	logging.log (logging.DEBUG, "Parsing information for DSA %s from wml file %s" % (dsa, filename))
	
	try:
		wmlFile = open(path)
		
		for line in wmlFile:
			line= line.decode ("ISO-8859-2")
				
			descrpatern = re.compile (r'description>(.*?)</define-tag>')
			result = descrpatern.search (line)
			if result:
				data["description"] = result.groups()[0]
				continue
				
			sinfopatern = re.compile (r'<define-tag moreinfo>(.*?)')
			result = sinfopatern.search (line)
			if result:
				moreinfo = True
				data["moreinfo"] = result.groups()[0] 
				continue
			
			einfopatern = re.compile (r'</define-tag>')
			if moreinfo and einfopatern.search (line):
				data["moreinfo"] = __parseMoreinfo(data["moreinfo"])
 				moreinfo = False
				continue
			
			if moreinfo:
				data["moreinfo"] += line
				continue
			
	except IOError:
		logging.log (logging.ERROR, "Can't work with file %s" % path)
	
	return (dsa, data)

def __parseMoreinfo (info):
	""" Remove unnecessary information form moreinfo tag"""

	p = re.compile ("<p>(.*?)</p>", re.DOTALL)
	paragraphs = [m.groups()[0]  for m in re.finditer(p, info)]
	result = ""

	for par in paragraphs:
		if re.match(re.compile("For the .* distribution"), par):
			break
		result += "\n" + par
	
	return result
