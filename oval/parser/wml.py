# -*- coding: utf-8 -*-
# oval.parser.wml - module to parse descriptions of 
# Debian Security Advisories stored in wml format.
# Extrected tags:
# 	<description>
#		<moreinfo>- Paragraphs before descriptions of
# each release status
#
# (c) 2016 Sebastien Delafond <sdelafond@gmail.com>
# (c) 2015 Nicholas Luedtke
# (c) 2007 Pavel Vinogradov   
# (c) 2004 Javier Fernandez-Sanguino                                                                                                    
# Licensed under the GNU General Public License version 2.

import re
import os
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
  deb_version = ""
  releases = {}
  dsa = os.path.splitext(os.path.basename(path))[0]
  filename = os.path.basename (path)
	
  logging.log (logging.DEBUG, "Parsing information for DSA %s from wml file %s" % (dsa, filename))
	
  try:

    wmlFile = open(path, encoding="ISO-8859-2").read()

    # find and replace \n and \r\n symbols
    lines = re.sub('(?<![\r\n])(\r?\n|\n?\r)(?![\r\n])', ' ', wmlFile)

    lines = lines.split('\n\n')
    dversion_pattern = re.compile(r'(%s)' % '|'.join(debianVersion.keys()), re.IGNORECASE)

    for line in lines:
      # find description part
      descrpatern = re.compile(r'description>(.*?)</define-tag>')
      description = descrpatern.search(line)
      if description:
        data["description"] = description.groups()[0]

      # find moreinfo part
      sinfopatern = re.compile(r'<define-tag moreinfo>(.*?)')
      einfopatern = re.compile(r'</define-tag>')
      if sinfopatern.search(line) and einfopatern.search(line):
        data['moreinfo'] = line
        data["moreinfo"] = __parseMoreinfo(data["moreinfo"])

      # find debian version
      dversion = dversion_pattern.search(line)
      if dversion:
        deb_version = dversion.groups()[0].lower()
      else:
         deb_version = ""

      # find fixed version
      new_version_pattern = re.compile(r'version ([0-9]+[.:]+[a-zA-Z0-9.+\-:~]+?)\.?(</p>|\s)')
      version = new_version_pattern.search(line)

      # add fixed version and debian release in releases dict
      if version and deb_version != "" and not debianVersion[deb_version] in releases:
        pack_ver = version.groups()[0]
        releases.update({debianVersion[deb_version]: {"all": {grabPackName(path): pack_ver}}})

  except IOError:
    logging.log (logging.ERROR, "Can't work with file %s" % path)

  logging.debug("... found wml data: %s" % data)
	
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


