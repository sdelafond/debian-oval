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
def parseFile (path, debianVersion):
  """ Parse wml file with description of Debian Security Advisories 
	
  Keyword arguments:
  path -- full path to wml file
	
  return list (dsa id, tags data)"""
	
  data = {}
  moreinfo = False
  pack_ver = ""
  deb_version = ""
  releases = {}

  dsa = os.path.basename(path)[:-5]
  filename = os.path.basename (path)
	
  logging.log (logging.DEBUG, "Parsing information for DSA %s from wml file %s" % (dsa, filename))
	
  try:
    wmlFile = open(path)

    dversion_pattern = re.compile(r'(%s)' % '|'.join(debianVersion.keys()), re.IGNORECASE)

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
#        continue

      result = dversion_pattern.search(line)
      if result:
        deb_version = result.groups()[0].lower()

      new_version_pattern = re.compile(r'version (.+?)\.(</p>|\s)')
      result = new_version_pattern.search(line)
      if result and deb_version != "":
        pack_ver = result.groups()[0]
        releases.update({debianVersion[deb_version]: {u"all": {grabPackName(path) : pack_ver}}})

  except IOError:
    logging.log (logging.ERROR, "Can't work with file %s" % path)
	
  return data, releases

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

def grabPackName(path):
    """
    :param path: full path to wml file
    :return: string: Package Name
    """

    try:
        wmlFile = open(path)
        package_name = re.compile (r'We recommend that you upgrade your (.*?) packages')
        for line in wmlFile:
            result = package_name.search(line)
            if result:
                return result.groups()[0]
    except IOError:
        logging.log (logging.ERROR, "Can't work with file %s" % path)
