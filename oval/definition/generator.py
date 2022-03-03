# -*- coding: utf-8 -*-
# oval.definition.generator - generate well-formed xml file with
# OVAL definitions of Debian Security Advisories.
# Use various optimizations to minimize result XML
#
# (c) 2016 Sebastien Delafond <sdelafond@gmail.com>
# (c) 2015 Nicholas Luedtke
# (c) 2007 Pavel Vinogradov            
# (c) 2004 Javier Fernandez-Sanguino                                                                                           
# Licensed under the GNU General Public License version 2.

import hashlib
import re
import logging
import datetime
from lxml import etree
from oval.definition.differ import differ
import re

# from http://boodebr.org/main/python/all-about-python-and-unicode#UNI_XML
RE_XML_ILLEGAL = '([\u0000-\u0008\u000b-\u000c\u000e-\u001f\ufffe-\uffff])' + '|' + '([%s-%s][^%s-%s])|([^%s-%s][%s-%s])|([%s-%s]$)|(^[%s-%s])' % (chr(0xd800),chr(0xdbff),chr(0xdc00),chr(0xdfff), chr(0xd800),chr(0xdbff),chr(0xdc00),chr(0xdfff), chr(0xd800),chr(0xdbff),chr(0xdc00),chr(0xdfff)) 
regex = re.compile(RE_XML_ILLEGAL)
nsmap = {
    None       : "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    "ind-def"  : "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent",
    "linux-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
    "oval"     : "http://oval.mitre.org/XMLSchema/oval-common-5",
    "oval-def" : "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    "unix-def" : "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix",
    "xsi"      : "http://www.w3.org/2001/XMLSchema-instance",
}

          
class OvalGeneratorException (Exception):
    pass

class CVEFormatException (OvalGeneratorException):
  code = 1
  
def __createXMLElement (name, descr = None, attrs = {}, nsmap = {}):
  """
    Create XML element with text descr and attributes attrs
    
    Keyword arguments:
    name -- Name of XML element
    descr -- content of textNode (default None)
    attrs -- attributes of element (default {})

    Return created XML element
  """

  element = etree.Element(name, attrs, nsmap=nsmap)
  
  if descr != None:
    for match in regex.finditer(descr):
      descr = descr[:match.start()] + "?" + descr[match.end():]
    element.text= descr

  return (element)

namespace = "oval:org.debian.oval"
tests = __createXMLElement ("tests")
objects = __createXMLElement ("objects")
states = __createXMLElement ("states")

testsCurId = 1
objectsCurId = 1
statesCurId = 1

releaseArchHash = {"2.0" : 2, "2.1" : 4, "2.2":  6, "3.0" : 11, "3.1" : 12, "4.0" : 11, "5.0": 12, "6.0": 11}
testsHash = {"arch" : {}, "release": {}, "obj": {}, "fileSte": {}, "unameSte" : {}, "dpkgSte": {}} 
#We need more info about alpha, arm, hppa, bmips, lmips
unameArchTable = {'i386' : 'i686', 'amd64' : 'x86-64', 'ia64' : 'ia64', 'powerpc' : 'ppc', 's390' : 's390x', 'm86k' : 'm86k'} 

def getOvalId(key):
  return int.from_bytes(hashlib.md5(key.encode()).digest(), 'big')

def __getNewId (type):
  """Generate new unique id for tests, objects or states
  
    Argument keqywords:
    type -- type of generated id test | object | state
    
    return Generate id like <namespace>:tst|obj|ste:<id>
  """
  global testsCurId, objectsCurId, statesCurId
    
  if type == "test":
    result = "%s:tst:%d" % (namespace, testsCurId)
    testsCurId += 1
    
  if type == "object":
    result = "%s:obj:%d" % (namespace, objectsCurId)
    objectsCurId += 1
    
  if type == "state":
    result = "%s:ste:%d" % (namespace, statesCurId)
    statesCurId += 1
  
  return (result)

def __createOVALDpkginfoObject (name):
  """ Generate OVAL dpkginfo_object definition """
  
  if name not in testsHash["obj"]:
    objectId = __getNewId ("object");
    object = __createXMLElement("dpkginfo_object",
      attrs={"id":objectId, 
        "version":"1",
        "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"})
    object.append ( __createXMLElement ("name", name))
    objects.append (object)

    testsHash["obj"][name] = objectId
  
  return (testsHash["obj"][name])

def __createOVALTextfilecontentObject (pattern, path = "/etc", filename = "debian_version"):
  """ Generate OVAL textfilecontent54_object definition """
  name = path + filename + pattern
  
  if name not in testsHash["obj"]:
    objectId = __getNewId ("object");
    object = __createXMLElement("textfilecontent54_object",
      attrs={"id":objectId, 
        "version":"1",
        "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"})
    object.append ( __createXMLElement ("path", path))
    object.append ( __createXMLElement ("filename", filename))
    object.append ( __createXMLElement ("pattern", pattern, attrs={"operation" : "pattern match"}))
    object.append ( __createXMLElement ("instance", "1", attrs={"datatype" : "int"}))
    objects.append (object)

    testsHash["obj"][name] = objectId
  
  return (testsHash["obj"][name])

def __createOVALUnameObject ():
  """ Generate OVAL uname_object definition """
  name = "uname_object"
  
  if name not in testsHash["obj"]:
    objectId = __getNewId ("object");
    object = __createXMLElement("uname_object",
      attrs={"id":objectId, 
        "version":"1",
        "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"})
    objects.append (object)

    testsHash["obj"][name] = objectId
  
  return (testsHash["obj"][name])

def __getEvr(value):
  """ Generate evr from version
  
  Prepend "0:" if no epoch already
  """
  if ":" not in value:
    value = "0:"+value
  return value

def __createOVALState (value, operation = "less than"):
  """ Generate OVAL state definition 
  
    Use state hash for optimization of resulted XML
  """
  #TODO: Add arch state generation
  if operation not in testsHash["dpkgSte"] or value not in testsHash["dpkgSte"][operation]:
    stateId = __getNewId ("state")

    state = __createXMLElement("dpkginfo_state", 
      attrs={"id":stateId, 
        "version":"1",
        "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"})
    state.append ( __createXMLElement ("evr", __getEvr(value),
                    {"datatype":"debian_evr_string", 
                     "operation":operation}))
    states.append (state)
  
    testsHash["dpkgSte"][operation] = {value : stateId}
    
  return (testsHash["dpkgSte"][operation][value])

def __createOVALUnameState (field, value, operation = "equals"):
  """ Generate OVAL uname state definition 
  
    Use unameArchTable to convert dsa arch to uname arch value
  """
  
  try:
    value = unameArchTable[value]
  except KeyError:
    pass

  #TODO: Add arch state generation
  if operation not in testsHash["unameSte"] or value not in testsHash["unameSte"][operation]:
    stateId = __getNewId ("state")

    state = __createXMLElement("uname_state", 
      attrs={"id":stateId, 
        "version":"1",
        "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"})
    state.append ( __createXMLElement (field, value,
                    {"operation":operation}))
    states.append (state)
  
    testsHash["unameSte"][operation] = {value : stateId}
    
  return (testsHash["unameSte"][operation][value])

def __createOVALTextfilecontentState (value, operation = "equals"):
  """ Generate OVAL state definition 
  
    Use state hash for optimization of resulted XML
  """
  #TODO: Add arch state generation
  if operation not in testsHash["fileSte"] or value not in testsHash["fileSte"][operation]:
    stateId = __getNewId ("state")

    state = __createXMLElement("textfilecontent54_state", 
      attrs={"id":stateId, 
        "version":"1",
        "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"})
    state.append ( __createXMLElement ("subexpression", value,
                    {"operation":operation}))
    states.append (state)
  
    testsHash["fileSte"][operation] = {value : stateId}
    
  return (testsHash["fileSte"][operation][value])
  
def __createDPKGTest(name, version):
  """ Generate OVAL DPKG test """
  
  ref = __getNewId ("test")
  test = __createXMLElement("dpkginfo_test", 
      attrs={"id":ref, 
        "version":"1", 
        "check":"all",
        "check_existence":"at_least_one_exists",
        "comment":"%s is earlier than %s" % (name, version),
        "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
      })
  test.append ( __createXMLElement("object", attrs={"object_ref" : __createOVALDpkginfoObject (name)}))
  test.append ( __createXMLElement("state", attrs={"state_ref" : __createOVALState (version)}))
  tests.append(test)

  return (ref)
  
def __createTest(testType, value):
  """ Generate OVAL test for release or architecture cases"""
  
  if value not in testsHash[testType]:
    comment = None
      
    ref = __getNewId("test")
    
    if testType == "release":
      objectId = __createOVALTextfilecontentObject ("(\d+)\.\d")
      comment = "Debian GNU/Linux %s is installed" % value
      
      test = __createXMLElement("textfilecontent54_test", 
        attrs={"id":ref, 
          "version":"1", 
          "check":"all",
          "check_existence":"at_least_one_exists",
          "comment":comment,
          "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
      })
      test.append ( __createXMLElement("object", attrs={"object_ref" : objectId}))
      test.append ( __createXMLElement("state", attrs={"state_ref" : __createOVALTextfilecontentState (value, "equals")}))
      
    else:
      objectId = __createOVALUnameObject ()
      comment = "Installed architecture is %s" % value
      
      test = __createXMLElement("uname_test", 
        attrs={"id":ref, 
          "version":"1", 
          "check":"all",
          "check_existence":"at_least_one_exists",
          "comment":comment,
          "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
      })
      test.append ( __createXMLElement("object", attrs={"object_ref" : objectId}))
      if value != "all":
        test.append ( __createXMLElement("state", attrs={"state_ref" : __createOVALUnameState ("processor_type", value, "equals")}))
    
    tests.append(test)
        
    testsHash[testType][value] = ref
  
  return (testsHash[testType][value])

def __createGeneratorHeader ():
  """
    Create OVAL definitions XML generator element.
    
    return  xml.dom.minidom.Document with header information
  """
  
  generator = etree.Element ("generator")

  generator.append ( __createXMLElement ("{%s}product_name" % nsmap['oval'], "Debian") )
  generator.append ( __createXMLElement ("{%s}schema_version" % nsmap['oval'], "5.11.2") )
  generator.append ( __createXMLElement ("{%s}timestamp" % nsmap['oval'], datetime.datetime.now().strftime ("%Y-%m-%dT%H:%M:%S.188-04:00")) )

  return (generator)

def createPlatformDefinition (release, data, cve):
  """ Generate OVAL definitions for current release
  
    Generate full criteria tree for specified release. Tests, states and objects 
    stored in global dictionaries.
    Use differ module for otimize generated tree.
    
    Argument keywords:
    release -- Debian release
    data -- dict with information about packages
    cve - CVE id
    
    return Generated XML fragment
  """
  #Raise exception if we receive too small data
  if len(data) == 0:
    logging.warning("CVE %s: Information of affected platforms is not available." % cve)
  
  softwareCriteria = __createXMLElement ("criteria", attrs = {"comment" : "Release section", "operator" : "AND"})
  softwareCriteria.append ( __createXMLElement ("criterion", attrs={"test_ref" : __createTest("release", release), "comment" : "Debian %s is installed" % release}))
    
  archCriteria = __createXMLElement ("criteria", attrs = {"comment" : "Architecture section", "operator" : "OR"})

  # Handle architecture independed section
  if "all" in data:
    archIndepCriteria = __createXMLElement ("criteria", attrs={"comment" : "Architecture independent section", "operator" : "AND"})
    
    archIndepCriteria.append ( __createXMLElement ("criterion", attrs = {"test_ref" : __createTest("arch", "all"), "comment" : "all architecture"}))
    #Build packages section only if we have more then one package
    if len (data["all"]) > 1:
      packageCriteria = __createXMLElement ("criteria", attrs={"comment" : "Packages section", "operator" : "OR"})
      archIndepCriteria.append (packageCriteria)
    else:
      packageCriteria = archIndepCriteria
      
    for pkg in data["all"].keys():
      packageCriteria.append ( __createXMLElement ("criterion", attrs = {"test_ref" : __createDPKGTest(pkg, data["all"][pkg]), "comment" : "%s DPKG is earlier than %s" % (pkg, data["all"][pkg])}))
  
    archCriteria.append (archIndepCriteria)

  # Optimize packages tree in 2 stages
  diff = differ ()
  for i in range(2):
    
    if i == 0:
      dsaData = data
    else:
      dsaData = diff.getDiffer()
    
    diff.Clean()  
    for (key, value) in dsaData.items():
      if key != "all":
        diff.compareElement(key, value)
    
    eq = diff.getEqual()
    di = diff.getDiffer()
    
    # Generate XML for optimized packages
    if (len(eq)):
      if len(diff.getArchs()) != releaseArchHash[release]:
        archDependCriteria = __createXMLElement ("criteria", attrs={"comment" : "Architecture depended section", "operator" : "AND"})
        
        supportedArchCriteria = __createXMLElement ("criteria", attrs={"comment" : "Supported architectures section", "operator" : "OR"})
        for arch in diff.getArchs():
          supportedArchCriteria.append ( __createXMLElement ("criterion", attrs = {"test_ref" : __createTest("arch", arch), "comment" : "%s architecture" % arch}))
          archDependCriteria.append (supportedArchCriteria)
    
      packageCriteria = __createXMLElement ("criteria", attrs={"comment" : "Packages section", "operator" : "OR"})
      for bpkg in eq.keys():
        packageCriteria.append ( __createXMLElement ("criterion", attrs = {"test_ref" : __createDPKGTest(bpkg, eq[bpkg]), "comment" : "%s DPKG is earlier than %s" % (bpkg, eq[bpkg])}))
      
      if len(diff.getArchs()) != releaseArchHash[release]:      
        archDependCriteria.append (packageCriteria)
        archCriteria.append (archDependCriteria)
      else:
        archCriteria.append (packageCriteria)
    
  # Generate XML for all other packages
  if len(di):
    archDependCriteria = __createXMLElement ("criteria", attrs={"comment" : "Architecture depended section", "operator" : "AND"})
      
    for (key, value) in di.items():
      supportedPlatformCriteria = __createXMLElement ("criteria", attrs={"comment" : "Supported platform section", "operator" : "AND"})
      supportedPlatformCriteria.append ( __createXMLElement ("criterion", attrs = {"test_ref" : __createTest("arch", key), "comment" : "%s architecture" % key}))
    
      packageCriteria = __createXMLElement ("criteria", attrs={"comment" : "Packages section", "operator" : "OR"})
          
      for bpkg in di[key].keys():
        packageCriteria.append ( __createXMLElement ("criterion", attrs = {"test_ref" : __createDPKGTest(bpkg, di[key][bpkg]), "comment" : "%s DPKG is earlier than %s" % (bpkg, di[key][bpkg])}))
        supportedPlatformCriteria.append (packageCriteria)
    
    archDependCriteria.append (supportedPlatformCriteria)
    archCriteria.append (archDependCriteria)
       
  softwareCriteria.append (archCriteria)
  
  return (softwareCriteria)

def createDefinition (cve, oval):
  """ Generate OVAL header of Definition tag
  
    Print general informaton about OVAL definition. Use createPlatformDefinition for generate criteria 
    sections for each affected release.
    
    Argument keywords:
    cve -- CVE dentificator
    oval -- CVE parsed data
  """
  if "release" not in oval:
    logging.warning("CVE %s: Release definition not well formatted. Ignoring this CVE." % cve)
    raise CVEFormatException
    
  if "packages" not in oval:
    logging.warning("CVE %s: Package information missed. Ignoring this CVE." % cve)
    oval["packages"] = ""
    return None

  if "title" not in oval:
    logging.warning("CVE %s: title information missed." % cve)
    oval["title"] = ""

  if "description" not in oval:
    logging.warning("CVE %s: Description information missed." % cve)
    oval["description"] = ""

  if "moreinfo" not in oval:
    logging.warning("CVE %s: Moreinfo information missed." % cve)
    oval["moreinfo"] = ""

  if "secrefs" not in oval:
    logging.warning("CVE %s: Secrefs information missed." % cve)
    oval["secrefs"] = ""

  ### Definition block: Metadata, Notes, Criteria
  ovalId = getOvalId(cve)
  if oval['title'].startswith('CVE'):
    definition = __createXMLElement ("definition", attrs = {"id" : "oval:org.debian:def:%s" % ovalId,
                                                            "version" : "1", "class" : "vulnerability"})
  elif oval['title'].startswith('DSA'):
    definition = __createXMLElement ("definition", attrs = {"id" : "oval:org.debian:def:%s" % ovalId,
                                                            "version" : "1", "class" : "patch"})

  ### Definition : Metadata : title, affected, reference, description ###
  metadata = __createXMLElement ("metadata")
  metadata.append (__createXMLElement ("title", oval["title"]))

  ### Definition : Metadata : Affected : platform, product ###
  affected = __createXMLElement ("affected", attrs = {"family" : "unix"})
  for platform in oval["release"]:
    affected.append ( __createXMLElement ("platform", "Debian GNU/Linux %s" % platform))
  affected.append ( __createXMLElement ("product", oval.get("packages")))
    
  metadata.append (affected)
  ### Definition : Metadata : Affected : END ###

  refpatern = re.compile (r'((CVE|CAN)-[\d-]+)')
  for ref in oval.get("secrefs"):
    result = refpatern.search(ref)
    if result:
      (ref_id, source) = result.groups()
      metadata.append ( __createXMLElement ("reference", attrs = {"source" : source, "ref_id" : ref_id, "ref_url" : "https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s" % ref_id}) )
  
  #TODO: move this info to other place
  metadata.append ( __createXMLElement ("description", oval["description"]))
  debianMetadata = __createXMLElement ("debian")
  dsa = oval.get("dsa", None)
  if dsa:
    debianMetadata.append(__createXMLElement("dsa", dsa))
  date = oval.get("date", None)
  if date:
    debianMetadata.append ( __createXMLElement ("date", date) )
  debianMetadata.append ( __createXMLElement ("moreinfo", oval["moreinfo"]))
  metadata.append (debianMetadata)
  definition.append ( metadata )

  ### Definition : Criteria ###
  if len(oval["release"]) > 1:
    #f we have more than one release - generate additional criteria section
    platformCriteria = __createXMLElement ("criteria", attrs = {"comment" : "Platform section", "operator" : "OR"})
    definition.append (platformCriteria)
  else:
    platformCriteria = definition
  
  for platform in oval["release"]:
    data = oval["release"][platform]
    platformCriteria.append (createPlatformDefinition(platform, data, cve))
    
  ### Definition : Criteria END ###

  return (definition)

def createOVALDefinitions (ovals):
  """ Generate XML OVAL definition tree for range of CVE
  
    Generate namespace section and use other functions to generate definitions,
    tests, objects and states subsections.
    
    return -- Generated OVAL XML definition 
  """
  root = __createXMLElement ("oval_definitions", 
      attrs= {
          "{%s}schemaLocation"% nsmap['xsi'] : "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd",
      }, nsmap=nsmap
      )
  root.append ( __createGeneratorHeader () )
  
  definitions = etree.SubElement (root, "definitions")
  
  keyids = list(ovals.keys())
  keyids.sort()
  for cve in keyids:
    try:
      # filter for CVEs
      if (not "CVE-" in cve) and (not 'DSA-' in cve):
        continue
      definitions.append(createDefinition(cve, ovals[cve]))
    except CVEFormatException:
      logging.log (logging.WARNING, "CVE %s: Bad data file. Ignoring this CVE." % cve)
      
  root.append(tests)
  root.append(objects)
  root.append(states)

  return root

def printOVALDefinitions (root):
  if len(root.find("definitions")):
    print(etree.tostring(root, pretty_print=True, encoding='UTF-8', xml_declaration=True).decode('utf-8'))
