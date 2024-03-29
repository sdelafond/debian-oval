# -*- coding: utf-8 -*-
# oval.parser.dsa - module to parse Debian Security Advisories files.
#
# Extrected tags:
#   <pagetitle>
#    <report_date>
#    <secrefs>
#    <packages>
#    <isvulnerable>
#    <fixed>
#
# (c) 2016 Sebastien Delafond <sdelafond@gmail.com>
# (c) 2015 Nicholas Luedtke
# (c) 2007 Pavel Vinogradov     
# (c) 2004 Javier Fernandez-Sanguino                                                                                                  
# Licensed under the GNU General Public License version 2.

import re
import os
import logging

# Format of data files is:
#<define-tag pagetitle>DSA-###-# PACKAGE</define-tag>                                                                                          
#<define-tag report_date>yyyy-mm-dd</define-tag>                                                                                               
#<define-tag secrefs>CAN|CVE-XXXX-XXXX</define-tag>                                                                                            
#<define-tag packages>PACKAGE</define-tag>                                                                                                     
#<define-tag isvulnerable>yes|no</define-tag>                                                                                                  
#<define-tag fixed>yes|no</define-tag>  
def parseFile (path):
  """ Parse data file with information of Debian Security Advisories 
  
  Keyword arguments:
  path -- full path to data file
  
  return list (dsa id, tags and packages data)"""
  

  data = {}
  deb_ver = None
  fdeb_ver = None
  
  filename = os.path.basename (path)

  dsa = os.path.basename(path)[:-5]
  logging.log (logging.DEBUG, "Parsing DSA %s from file %s" % (dsa, filename))

  dsaFile = open(path, encoding="ISO-8859-2")
  
  for line in dsaFile:
    logging.debug(". looking at line: " + line.strip())
    datepatern = re.compile (r'report_date>([\d-]+)</define-tag>')
    result = datepatern.search (line)
    if result:
      date = result.groups()[0]
      normDate = lambda date: "-".join([(len(p) > 1 and p or "0"+p) for p in date.split("-")])
      data["date"] = normDate(date)
    
    descrpatern = re.compile (r'pagetitle>(.*?)</define-tag>')
    result = descrpatern.search (line)
    if result:
      data["title"] = result.groups()[0]
      logging.debug(".. extracted page title: " + data["title"])
      continue
    
    refspatern = re.compile (r'secrefs>(.*?)</define-tag>')
    result = refspatern.search (line)
    if result:
      data["secrefs"] = [str(s) for s in re.split(r'\s+', result.groups()[0])]
      logging.debug(".. extracted security references: %s" % (data["secrefs"],))

    pakpatern = re.compile (r'packages>(.*?)</define-tag>')
    result = pakpatern.search (line)
    if result:
      data["packages"] = result.groups()[0]
      logging.debug(".. extracted packages: " + data["packages"])

    vulpatern = re.compile (r'isvulnerable>(.*?)</define-tag>')
    result = vulpatern.search (line)
    if result:
      data["vulnerable"] = result.groups()[0]
      logging.debug(".. extracted vulnerable: " + data["vulnerable"])

    fixpatern = re.compile (r'fixed>(.*?)</define-tag>')
    result = fixpatern.search (line)
    if result:
      data["fixed"] = result.groups()[0]
      logging.debug(".. extracted fixed: " + data["fixed"])

    versionpatern = re.compile (r'<h3>Debian GNU/Linux (\d.\d) \((.*?)\)</h3>')
    result = versionpatern.search (line)
    if result:
      fdeb_ver = result.groups()[0]

    # Alternative format for data files
    versionpatern = re.compile (r'affected_release>([\d\.]+)<')
    result = versionpatern.search (line)
    if result:
      fdeb_ver = result.groups()[0]

      if fdeb_ver:
        deb_ver = fdeb_ver 
        fdeb_ver = None
      if "release" in data:
        if deb_ver in data["release"]:
          logging.warning("DSA %s: Found second files section for release %s" % (dsa, deb_ver))
        else:
          data["release"][deb_ver] = {}
      else:
        data["release"] = {deb_ver: {}}

    # Binary packages are pushed into array
    # Those are prepended by fileurls
    # TODO: Packages do _NOT_ include epochs 
    # (that should be fixed)
    if "release" in data and deb_ver:
      urlpatern = re.compile (r'fileurl [\w:/.\-+]+/([\w\-.+~]+)\.deb[^i]')
      result = urlpatern.search (line)
      if result:
        (package, version, architecture) = result.groups()[0].split("_")
          
        if architecture in data["release"][deb_ver]:
          data["release"][deb_ver][architecture][package] = version
        else:
          data["release"][deb_ver][architecture] = {package : version}

  logging.debug("... found dsa data: %s" % data )
  
  if "title" in data:
    return data["title"], data
