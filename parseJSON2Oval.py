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
from datetime import date
import oval.definition.generator
from oval.parser import dsa
from oval.parser import wml


dsaref = {}

# TODO: these may need changed or reworked.
DEBIAN_VERSION = {"wheezy" : "7.0", "jessie" : "8.2", "stretch" : "9.0",
                  "sid" : "9.0", "etch" : "4.0", "squeeze":"6.0", "lenny":"5.0"}

def usage (prog = "parse-wml-oval.py"):
    """Print information about script flags and options"""

    print """usage: %s [vh] [-d <directory>]\t-d\twhich directory use for
    dsa definition search\t-v\tverbose mode\t-h\tthis help""" % prog


def printdsas(dsaref):
    """ Generate and print OVAL Definitions for collected DSA information """

    ovalDefinitions = oval.definition.generator.createOVALDefinitions (dsaref)
    oval.definition.generator.printOVALDefinitions (ovalDefinitions)


def parsedirs (directory, postfix, depth):
    """ Recursive search directory for DSA files contain postfix in their names.
    For this files called oval.parser.dsa.parseFile() for extracting DSA
    information.
    """
    for file in os.listdir (directory):
		
        path = "%s/%s" % (directory, file)
        logging.log (logging.DEBUG, "Checking %s (for %s at %s)" % (file, postfix, depth))
		
        if os.access(path, os.R_OK) and os.path.isdir (path) and not os.path.islink (path) and file[0] != '.':
            logging.log(logging.DEBUG, "Entering directory " + path)
            parsedirs (path, postfix, depth-1)

        #Parse DSA data files
        if os.access(path, os.R_OK) and file.endswith(postfix) and file[0] != '.' and file[0] != '#':
            result = dsa.parseFile(path)
            if result:
                if dsaref.has_key(result[0]):
                    for (k, v) in result[1].iteritems():
                        dsaref[result[0]][k] = v
                else:
                    dsaref[result[0]] = result[1]

        #Parse DSA wml descriptions
        if os.access(path, os.R_OK) and file.endswith(".wml") and file[0] != '.' and file[0] != '#':
            result = wml.parseFile(path)
            if result:
                if dsaref.has_key(result[0]):
                    for (k, v) in result[1].iteritems():
                        dsaref[result[0]][k] = v
                    if not dsaref[result[0]].has_key("release"):
                        dsaref[result[0]]['release']=result[2]
                else:
                    dsaref[result[0]] = result[1]
                    dsaref[result[0]]['release']=result[2]
    return 0


def parseJSON(json_data, id_num, year):
    """
    Parse the JSON data and extract information needed for OVAL definitions
    :param id_num: int id number to start at for defintions
    :param json_data: Json_Data
    :return:
    """
    today = date.today()
    logging.log(logging.DEBUG, "Start of JSON Parse.")
    d_num = id_num
    for package in json_data:
        logging.log(logging.DEBUG, "Parsing package %s" % package)
        for CVE in json_data[package]:
            if CVE.find(year) < 0:
                continue
            logging.log(logging.DEBUG, "Getting releases for %s" % CVE)
            release = {}
            for rel in json_data[package][CVE]['releases']:
                if json_data[package][CVE]['releases'][rel]['status'] != \
                        'resolved':
                    fixed_v = '0'
                    f_str = 'no'
                else:
                    fixed_v = json_data[package][CVE]['releases'][rel]['fixed_version']
                    f_str = 'yes'
                release.update({DEBIAN_VERSION[rel]: {u'all': {
                    package: fixed_v}}})

                dsaref.update({str(d_num): {"packages": package,
                                           'description': "",
                                    'vulnerable': "yes",
                                    'date': str(today.isoformat()),
                                    'fixed': f_str, 'moreinfo': "",
                                    'release': release, 'secrefs': CVE}})
                logging.log(logging.DEBUG, "Created entry in dsaref %s" % d_num)
                d_num += 1


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
        logging.basicConfig(level=logging.WARNING)

    # unpack args

    json_file = args['JSONfile']
    temp_file = args['tmp']
    year = args['year']
    id_num = args['id']

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
        call(args)
        logging.log(logging.DEBUG, "File %s received" % temp_file)
        json_data = get_json_data(temp_file)
        if os.path.isfile(temp_file):
            logging.log(logging.DEBUG, "Removing file %s" % temp_file)
            os.remove(temp_file)

    parseJSON(json_data, id_num, year)
    #parsedirs (opts['-d'], '.data', 2)
    logging.log(logging.INFO, "Finished parsing JSON data")
    printdsas(dsaref)

if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(description='Generates oval definitions '
                                                 'from the JSON file used to '
                                                 'build the Debian Security '
                                                 'Tracker.')
    PARSER.add_argument('-v', '--verbose', help='Verbose Mode',
                        action="store_true")
    PARSER.add_argument('-j', '--JSONfile', type=str,
                        help='Local JSON file to use. This will use a local '
                             'copy of the JSON file instead of downloading from'
                             ' it from the server. default=none', default=None)
    PARSER.add_argument('-t', '--tmp', type=str,
                        help='Temporary file to download JSON file to. Warning:'
                             ' if this file already exists it will be removed '
                             'prior to downloading the JSON file. default= '
                             './DebSecTrackTMP.t', default='./DebSecTrackTMP.t')
    PARSER.add_argument('-y', '--year', type=str,
                        help='Limit to this year. default= ' '2016', default='2016')
    PARSER.add_argument('-i', '--id', type=int,
                        help='id number to start defintions at. default=100',
                        default=100)
    ARGS = vars(PARSER.parse_args())
    main(ARGS)



