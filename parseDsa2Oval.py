#!/usr/bin/python
# -*- coding: utf-8 -*-
# Extracts the data DSA files and creates OVAL queries to
# be used with the OVAL query interpreter (see http://oval.mitre.org)

# (c) 2007 Pavel Vinogradov
# (c) 2004 Javier Fernandez-Sanguino                                                                                                           
# Licensed under the GNU General Public License version 2.                                                                                     
                                                                                                                                               
import os
import sys
import getopt
import logging

import oval.definition.generator
from oval.parser import dsa
from oval.parser import wml

ovals = {}

def usage (prog = "parse-wml-oval.py"):
  """Print information about script flags and options"""

  print """
usage: %s [vh] [-d <directory>]
\t-d\twhich directory use for dsa definition search
\t-v\tverbose mode
\t-h\tthis help
  """ % prog
   
def printdsas (ovals):
    """ Generate and print OVAL Definitions for collected DSA information """
    
    ovalDefinitions = oval.definition.generator.createOVALDefinitions (ovals)
    oval.definition.generator.printOVALDefinitions (ovalDefinitions)

def parsedirs (directory, postfix, depth):
  """ Recursive search directory for DSA files contain postfix in their names.

    For this files called oval.parser.dsa.parseFile() for extracting DSA information.
  """

  global ovals

  if depth == 0:
    logging.log(logging.DEBUG, "Maximum depth reached at directory " + directory)
    return (0)
  
  for file in os.listdir (directory):
    
    path = "%s/%s" % (directory, file)
    
    logging.log (logging.DEBUG, "Checking %s (for %s at %s)" % (file, postfix, depth))
    
    if os.access(path, os.R_OK) and os.path.isdir (path) and not os.path.islink (path) and file[0] != '.':
      logging.log(logging.DEBUG, "Entering directory " + path)
      parsedirs (path, postfix, depth-1)

    #Parse files
    if os.access(path, os.R_OK) and file.endswith(postfix) and file[0] != '.' and file[0] != '#':
      result = dsa.parseFile (path)
      if result:
        if ovals.has_key (result[0]):
          for (k, v) in result[1].iteritems():
            ovals[result[0]][k] = v
        else:
          ovals[result[0]] = result[1]

        # also parse corresponding wml file
        wmlResult = wml.parseFile(path.replace('.data', '.wml'))
        if wmlResult:
          data, releases = wmlResult
          for (k, v) in data.iteritems():
            ovals[result[0]][k] = v
          if not ovals[result[0]].get("release", None):
            ovals[result[0]]['release']=releases

  return 0

if __name__ == "__main__":
    
    # Parse cmd options with getopt
    opts = {}
    
    #By default we search dsa definitions from current directory, but -d option override this
    opts['-d'] = "./"
    
    try:
        opt, args = getopt.getopt (sys.argv[1:], 'vhd:')
    except getopt.GetoptError:
        usage ()
        sys.exit(1)
    
    for key, value in opt:
        opts[key] = value
    
    if opts.has_key ('-h'):
        usage()
        sys.exit(0)
        
    if opts.has_key('-v'):
        logging.basicConfig(level=logging.DEBUG)
        
    logging.basicConfig(level=logging.WARNING)
        
    parsedirs (opts['-d'], '.data', 2)
    printdsas(ovals)
