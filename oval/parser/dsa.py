# -*- coding: utf-8 -*-
# oval.parser.dsa - module to parse Debian Security Advisories files.
#
# Extrected tags:
# 	<pagetitle>
#		<report_date>
#		<secrefs>
#		<packages>
#		<isvulnerable>
#		<fixed>
#
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
	
	filename = os.path.basename (path)

	patern = re.compile(r'dsa-(\d+)')
	result = patern.search(filename)
	if result:
		dsa = result.groups()[0]
	else:
		logging.log(logging.WARNING, "File %s does not look like a proper DSA, not checking" % filename)
		return (None)

	logging.log (logging.DEBUG, "Parsing DSA %s from file %s" % (dsa, filename))

	dsaFile = open(path)
	
	for line in dsaFile:
		line= line.decode ("ISO-8859-2")
		datepatern = re.compile (r'report_date>([\d-]+)</define-tag>')
		result = datepatern.search (line)
		if result:
			date = result.groups()[0]
			normDate = lambda (date): "-".join([(len(p) > 1 and p or "0"+p) for p in date.split("-")])
			data["date"] = normDate(date)
		
		refspatern = re.compile (r'secrefs>(.*?)</define-tag>')
		result = refspatern.search (line)
		if result:
			data["secrefs"] = result.groups()[0]
			logging.log(logging.DEBUG, "Extracted security references: " + data["secrefs"])

		pakpatern = re.compile (r'packages>(.*?)</define-tag>')
		result = pakpatern.search (line)
		if result:
			data["packages"] = result.groups()[0]

		vulpatern = re.compile (r'isvulnerable>(.*?)</define-tag>')
		result = vulpatern.search (line)
		if result:
			data["vulnarable"] = result.groups()[0]

		fixpatern = re.compile (r'fixed>(.*?)</define-tag>')
		result = fixpatern.search (line)
		if result:
			data["fixed"] = result.groups()[0]

		versionpatern = re.compile (r'<h3>Debian GNU/Linux (\d.\d) \((.*?)\)</h3>')
		result = versionpatern.search (line)
		if result:
			deb_ver = result.groups()[0]
			
			if data.has_key("release"):
				if data["release"].has_key(deb_ver):
					logging.log(logging.WARNING, "DSA %s: Found second files section for release %s" % (dsa, deb_ver))
				else:
					data["release"][deb_ver] = {}
			else:
				data["release"] = {deb_ver: {}}
		# Binary packages are pushed into array
		# Those are prepended by fileurls
		# TODO: Packages do _NOT_ include epochs 
		# (that should be fixed)
		if data.has_key("release") and deb_ver:
			urlpatern = re.compile (r'fileurl [\w:/.\-+]+/([\w\-.+~]+)\.deb[^i]')
			result = urlpatern.search (line)
			if result:
				(package, version, architecture) = result.groups()[0].split("_")
					
				if data["release"][deb_ver].has_key(architecture):
					data["release"][deb_ver][architecture][package] = version
				else:
					data["release"][deb_ver][architecture] = {package : version}
	
	return (dsa, data)
