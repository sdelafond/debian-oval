#!/usr/bin/python
# -*- coding: utf-8 -*-
# Extracts the data from the security tracker and creates OVAL queries to
# be used with the OVAL query interpreter (see http://oval.mitre.org)

# (c) 2016 Sebastien Delafond <sdelafond@gmail.com>
# (c) 2015 Nicholas Luedtke
# Licensed under the GNU General Public License version 2.                                                                                     

import os
from subprocess import call
import sys
import logging
import argparse
import json
import re
from datetime import date
import oval.definition.generator
from oval.parser import dsa
from oval.parser import wml


ovals = {}

# TODO: 
# - these may need changed or reworked.
# - ideally this would d be extracted from the release information @ website
DEBIAN_VERSION = { 
    "potato" : "2",
    "sarge"  : "3",
    "woody"  : "3",
    "etch"   : "4",
    "lenny"  : "5",
    "squeeze": "6",
    "wheezy" : "7",
    "jessie" : "8",
    "stretch": "9",
    "buster" : "10",
    "bullseye" : "11",
    "sid" : "1000"}

def usage (prog = "parse-wml-oval.py"):
    """Print information about script flags and options"""

    print("""usage: %s [vh] [-d <directory>]\t-d\twhich directory use for
    dsa definition search\t-v\tverbose mode\t-h\tthis help""" % prog)
def printdsas(ovals):
    """ Generate and print OVAL Definitions for collected DSA information """
    import pprint
    logging.debug(pprint.pformat(ovals))
    ovalDefinitions = oval.definition.generator.createOVALDefinitions(ovals)
    oval.definition.generator.printOVALDefinitions(ovalDefinitions)

def add_dsa_wml_to_cve(dsaResult, wmlResult, dsaRef, debian_release):

    global ovals
    debian_version = DEBIAN_VERSION[debian_release]

    secrefs = dsaResult[1].get('secrefs', [])
    logging.debug("working on SECREFS: %s" % (secrefs,))

    # tack on dsaRef to make sure we always create a DSA entry even if
    # this DSA was not linked to any bug number (see comment below)
    for key in secrefs + [dsaRef,]:
        logging.debug("working on secref %s" % (key,))
        if not key.startswith('CVE'):
            # either a bug number, or the dsaRef itself: in this case
            # we want to generate one *single* entry with a dsaRef
            # key. It will later be exported as a patch/advisory OVAL
            # entity
            key = dsaRef
            if key in ovals:
                # we've already added and enriched that dsaRef entry
                continue
            else:
                logging.debug("new entry %s: %s" % (key, dsaResult[1]))
                ovals[key] = dsaResult[1]
        elif key not in ovals:
            # this secref is listed in a DSA, but was not present in
            # the JSON export: nothing to enrich
            continue

        # add info from .data file
        logging.debug("enriching existing entry %s with %s" % (key, dsaResult[1]))
        for (k, v) in dsaResult[1].items():
            if k not in ovals[key]:
                ovals[key][k] = v

        # skip if the wml file does not contain the debian release
        if debian_version in wmlResult[1]:
            # add info from .wml file to CVE in
            add_wml_result(wmlResult, key, dsaRef, debian_release)


def add_wml_result(wmlResult, key, dsaRef, debian_release):

    global ovals
    debian_version = DEBIAN_VERSION[debian_release]
    entry = ovals[key]
    wml_data, releases = wmlResult
    logging.debug("enriching existing entry %s with %s" % (key, wml_data))

    for (k, v) in wml_data.items():
        if k == "moreinfo" and k not in entry:
            entry['dsa'] = dsaRef
            entry[k] = v.replace('\n', ' ').strip()
        elif k == 'description' and k not in entry:
            entry[k] = v
        else:
            entry[k] = v
    if "release" not in entry:
        entry["release"] = {}
    entry['release'].update({debian_version: releases[debian_version]})


def parsedirs(directory, regex, depth, debian_release):
  """ Recursive search directory for DSA files contain postfix in their names.

    For this files called oval.parser.dsa.parseFile() for extracting DSA information.
  """

  global ovals
  debian_version = DEBIAN_VERSION[debian_release]

  if depth == 0:
    logging.log(logging.DEBUG, "Maximum depth reached at directory " + directory)
    return 0

  for fileName in os.listdir(directory):
    path = "%s/%s" % (directory, fileName)
    logging.log(logging.DEBUG, "Checking %s (for %s at %s)" % (fileName, regex.pattern, depth))

    if os.access(path, os.R_OK) and os.path.isdir(path) and not os.path.islink(path) and fileName[0] != '.':
      logging.log(logging.DEBUG, "Entering directory " + path)
      parsedirs(path, regex, depth-1, debian_release)

    # parse fileNames
    if os.access(path, os.R_OK) and regex.search(fileName) and fileName[0] != '.' and fileName[0] != '#':
      dsaResult = dsa.parseFile(path)

      # also parse corresponding wml file
      wmlResult = wml.parseFile(path.replace('.data', '.wml'), DEBIAN_VERSION)

      # remove .data extension
      dsaRef = os.path.splitext(fileName)[0].upper()

      if dsaResult and wmlResult:
        # add data from .data files to cve in ovals dict
        add_dsa_wml_to_cve(dsaResult, wmlResult, dsaRef, debian_release)

        # add info about DSA in ovals dict
        dsa_title, dsa_data = dsaResult

        # add DSA to ovals dict
        if debian_version not in wmlResult[1]:
          continue
  return 0


def parseJSON(json_data, debian_release):
    """
    Parse the JSON data and extract information needed for OVAL definitions
    :param json_data: Json_Data
    :return:
    """
    global ovals

    logging.log(logging.DEBUG, "Start of JSON Parse.")
    for package in json_data:
        logging.log(logging.DEBUG, "Parsing package %s" % package)
        for cve in json_data[package]:
            logging.log(logging.DEBUG, "Getting releases for %s" % cve)
            release = {}
            for rel in json_data[package][cve]['releases']:
                status = json_data[package][cve]['releases'][rel]['status']
                f_str = 'no'

                if status == 'resolved':
                    fixed_v = json_data[package][cve]['releases'][rel]['fixed_version']
                    f_str = 'yes'
                else:
                    fixed_v = '0'
                    f_str = 'no'

                if status == 'resolved' and fixed_v == '0':
                    # This CVE never impacted the given release
                    logging.log(logging.DEBUG, "Release %s not affected by %s" % (rel, cve))
                    continue

                if debian_release == rel:
                    release.update({DEBIAN_VERSION[rel]: {'all': {
                        package: fixed_v}}})
                    ovals.update({cve: {"packages": package,
                                        'title': cve,
                                        'vulnerable': "yes",
                                        'date': None,
                                        'fixed': f_str,
                                        'description': json_data[package][cve].get("description", ""),
                                        'secrefs': (cve,),
                                        'release': release}})
                    logging.log(logging.DEBUG, "Created entry for %s: %s" % (cve, ovals[cve]))


def get_json_data(json_file):
    """
    Retrieves JSON formatted data from a file.
    :param json_file:
    :return: JSON data (dependent on the file loaded, usually a dictionary.)
    """
    logging.log(logging.DEBUG, "Extracting JSON file %s" % json_file)
    with open(json_file, "r") as json_d:
        d = json.load(json_d)
    return d


def main(args):
    """
    Main function for parseJSON2Oval.py
    :param args:
    :return:
    """

    if args['verbose']:
        logging.basicConfig(level=logging.DEBUG)
    else:
        if args['quiet']:
            logging.basicConfig(level=logging.ERROR)
        else:
            logging.basicConfig(level=logging.WARNING)

    # unpack args
    json_file = args['JSONfile']
    data_dir = args['data_directory']
    temp_file = args['tmp']
    release = args['release']

    if json_file:
        json_data = get_json_data(json_file)
    else:
        logging.log(logging.DEBUG, "Preparing to download JSONfile")
        if os.path.isfile(temp_file):
            logging.log(logging.WARNING, "Removing file %s" % temp_file)
            os.remove(temp_file)
        logging.log(logging.DEBUG, "Issuing wget for JSON file")
        args = ['wget', 'https://security-tracker.debian.org/tracker/data/json',
                '-O', temp_file]
        if os.path.isdir('/etc/ssl'):
            if os.path.isdir('/etc/ssl/ca-debian'):
                args.insert(1, '--ca-directory=/etc/ssl/ca-debian')
        call(args)
        logging.log(logging.DEBUG, "File %s received" % temp_file)
        json_data = get_json_data(temp_file)
        if os.path.isfile(temp_file):
            logging.log(logging.DEBUG, "Removing file %s" % temp_file)
            os.remove(temp_file)

    parseJSON(json_data, release)
    parsedirs(data_dir, re.compile('^dsa.+\.data$'), 2, release)
    parsedirs(data_dir, re.compile('^dla.+\.data$'), 2, release)
    logging.log(logging.INFO, "Finished parsing JSON data")
    printdsas(ovals)

if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(description='Generates oval definitions '
                                                 'from the JSON file used to '
                                                 'build the Debian Security '
                                                 'Tracker.')
    PARSER.add_argument('-q', '--quiet', help='Quiet mode', action="store_true")
    PARSER.add_argument('-v', '--verbose', help='Verbose Mode',
                        action="store_true")
    PARSER.add_argument('-j', '--JSONfile', type=str,
                        help='Local JSON file to use. This will use a local '
                             'copy of the JSON file instead of downloading from'
                             ' it from the server. default=none', default=None)
    PARSER.add_argument('-d', '--data-directory', type=str,
                        help='Local directory to parse for data/wml file.'
                        'default=.', default='.')
    PARSER.add_argument('-t', '--tmp', type=str,
                        help='Temporary file to download JSON file to. Warning:'
                             ' if this file already exists it will be removed '
                             'prior to downloading the JSON file. default= '
                             './DebSecTrackTMP.t', default='./DebSecTrackTMP.t')
    PARSER.add_argument('-r', '--release', type=str,
                        help='Limit to this release. default= jessie', default='jessie')
    PARSER.add_argument('-i', '--id', type=int,
                        help='id number to start defintions at. default=100',
                        default=100)
    ARGS = vars(PARSER.parse_args())
    main(ARGS)



