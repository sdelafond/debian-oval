# -*- coding: utf-8 -*-
# oval.definitio.generator - generate well-formed xml file with 
# OVAL definitions of Debian Security Advisories.
# Use various optimizations to minimize result XML
#
# (c) 2007 Pavel Vinogradov            
# (c) 2004 Javier Fernandez-Sanguino                                                                                           
# Licensed under the GNU General Public License version 2.

import re
import logging
import datetime
import xml.dom.ext
import xml.dom.minidom
from oval.definition.differ import differ
					
class OvalGeneratorException (Exception):
    pass

class DSAFormatException (OvalGeneratorException):
	code = 1
	
def __createXMLElement (name, descr = None, attrs = {}):
	"""
		Create XML element with text descr and attributes attrs
		
		Keyword arguments:
		name -- Name of XML element
		descr -- content of textNode (default None)
		attrs -- attributes of element (default {})

		Return created XML element
	"""

	doc = xml.dom.minidom.Document ()
	element = doc.createElement (name)
	
	for (attr, value) in attrs.items():
		attribute = doc.createAttribute (attr)
		attribute.value = value
		element.attributes.setNamedItem (attribute)
	
	if descr != None:
		description = doc.createTextNode (descr.encode("utf8"))
		element.appendChild (description)
	
	return (element)

namespace = "oval:org.debian.oval"
tests = __createXMLElement ("tests")
objects = __createXMLElement ("objects")
states = __createXMLElement ("states")

testsCurId = 1
objectsCurId = 1
statesCurId = 1

releaseArchHash = {"2.0" : 2, "2.1" : 4, "2.2":  6, "3.0" : 11, "3.1" : 12, "4.0" : 11}
testsHash = {"arch" : {}, "release": {}, "obj": {}, "fileSte": {}, "unameSte" : {}, "dpkgSte": {}} 
#We need more info about alpha, arm, hppa, bmips, lmips
unameArchTable = {'i386' : 'i686', 'amd64' : 'x86-64', 'ia64' : 'ia64', 'powerpc' : 'ppc', 's390' : 's390x', 'm86k' : 'm86k'} 

def __trimzero (val):
	value = val[:]
	while value[0] == "0":
		value = value[1:]
	return value

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
	
	if not testsHash["obj"].has_key(name):
		objectId = __getNewId ("object");
		object = __createXMLElement("dpkginfo_object",
			attrs={"id":objectId, 
				"version":"1",
				"xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"})
		object.appendChild ( __createXMLElement ("name", name))
		objects.appendChild (object)

		testsHash["obj"][name] = objectId
	
	return (testsHash["obj"][name])

def __createOVALTextfilecontentObject (pattern, path = "/etc", filename = "debian_version"):
	""" Generate OVAL textfilecontent_object definition """
	name = path + filename + pattern
	
	if not testsHash["obj"].has_key(name):
		objectId = __getNewId ("object");
		object = __createXMLElement("textfilecontent_object",
			attrs={"id":objectId, 
				"version":"1",
				"xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"})
		object.appendChild ( __createXMLElement ("path", path))
		object.appendChild ( __createXMLElement ("filename", filename))
		object.appendChild ( __createXMLElement ("line", pattern, attrs={"operation" : "pattern match"}))
		objects.appendChild (object)

		testsHash["obj"][name] = objectId
	
	return (testsHash["obj"][name])

def __createOVALUnameObject ():
	""" Generate OVAL textfilecontent_object definition """
	name = "uname_object"
	
	if not testsHash["obj"].has_key(name):
		objectId = __getNewId ("object");
		object = __createXMLElement("uname_object",
			attrs={"id":objectId, 
				"version":"1",
				"xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"})
		objects.appendChild (object)

		testsHash["obj"][name] = objectId
	
	return (testsHash["obj"][name])

def __createOVALState (value, operation = "less than"):
	""" Generate OVAL state definition 
	
		Use state hash for optimization of resulted XML
	"""
	#TODO: Add arch state generation
	if not testsHash["dpkgSte"].has_key(operation) or not testsHash["dpkgSte"][operation].has_key(value):
		stateId = __getNewId ("state")

		state = __createXMLElement("dpkginfo_state", 
			attrs={"id":stateId, 
				"version":"1",
				"xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"})
		state.appendChild ( __createXMLElement ("evr", "0:"+value, 
						  			{"datatype":"evr_string", 
									   "operation":operation}))
		states.appendChild (state)
	
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
	if not testsHash["unameSte"].has_key(operation) or not testsHash["unameSte"][operation].has_key(value):
		stateId = __getNewId ("state")

		state = __createXMLElement("uname_state", 
			attrs={"id":stateId, 
				"version":"1",
				"xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"})
		state.appendChild ( __createXMLElement (field, value, 
						  			{"operation":operation}))
		states.appendChild (state)
	
		testsHash["unameSte"][operation] = {value : stateId}
		
	return (testsHash["unameSte"][operation][value])

def __createOVALTextfilecontentState (value, operation = "equals"):
	""" Generate OVAL state definition 
	
		Use state hash for optimization of resulted XML
	"""
	#TODO: Add arch state generation
	if not testsHash["fileSte"].has_key(operation) or not testsHash["fileSte"][operation].has_key(value):
		stateId = __getNewId ("state")

		state = __createXMLElement("textfilecontent_state", 
			attrs={"id":stateId, 
				"version":"1",
				"xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"})
		state.appendChild ( __createXMLElement ("line", value, 
						  			{"operation":operation}))
		states.appendChild (state)
	
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
	test.appendChild ( __createXMLElement("object", attrs={"object_ref" : __createOVALDpkginfoObject (name)}))
	test.appendChild ( __createXMLElement("state", attrs={"state_ref" : __createOVALState (version)}))
	tests.appendChild(test)

	return (ref)
	
def __createTest(testType, value):
	""" Generate OVAL test for release or architecture cases"""
	
	if not testsHash[testType].has_key(value):
		comment = None
			
		ref = __getNewId("test")
		
		if testType == "release":
			objectId = __createOVALTextfilecontentObject ("\d\.\d")
			comment = "Debian GNU/Linux %s is installed" % value
			
			test = __createXMLElement("textfilecontent_test", 
				attrs={"id":ref, 
					"version":"1", 
					"check":"all",
					"check_existence":"at_least_one_exists",
					"comment":comment,
					"xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
			})
			test.appendChild ( __createXMLElement("object", attrs={"object_ref" : objectId}))
			test.appendChild ( __createXMLElement("state", attrs={"state_ref" : __createOVALTextfilecontentState (value, "equals")}))
			
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
			test.appendChild ( __createXMLElement("object", attrs={"object_ref" : objectId}))
			if value != "all":
				test.appendChild ( __createXMLElement("state", attrs={"state_ref" : __createOVALUnameState ("processor_type", value, "equals")}))
		
		tests.appendChild(test)
				
		testsHash[testType][value] = ref
	
	return (testsHash[testType][value])

def __createGeneratorHeader ():
	"""
		Create OVAL definitions XML generator element.
		
		return  xml.dom.minidom.Document with header information
	"""
	
	doc = xml.dom.minidom.Document ()
	generator = doc.createElement ("generator")

	generator.appendChild ( __createXMLElement ("oval:product_name", "Debian") )
	generator.appendChild ( __createXMLElement ("oval:schema_version", "5.3") )
	generator.appendChild ( __createXMLElement ("oval:timestamp", datetime.datetime.now().strftime ("%Y-%m-%dT%H:%M:%S.188-04:00")) )

	return (generator)

def createPlatformDefinition (release, data, dsa):
	""" Generate OVAL definitions for current release
	
		Generate full criteria tree for specified release. Tests, states and objects 
		stored in global dictionaries.
		Use differ module for otimize generated tree.
		
		Argument keywords:
		release -- Debian release
		data -- dict with information about packages
		dsa - DSA id
		
		return Generated XML fragment
	"""
	#Raise excetion if we receive too small data
	if len(data) == 0:
		raise DSAFormatException
	
	softwareCriteria = __createXMLElement ("criteria", attrs = {"comment" : "Release section", "operator" : "AND"})
	softwareCriteria.appendChild ( __createXMLElement ("criterion", attrs={"test_ref" : __createTest("release", release), "comment" : "Debian %s is installed" % release}))
		
	archCriteria = __createXMLElement ("criteria", attrs = {"comment" : "Architecture section", "operator" : "OR"})

	# Handle architecture independed section
	if data.has_key ("all"):
		archIndepCriteria = __createXMLElement ("criteria", attrs={"comment" : "Architecture independet section", "operator" : "AND"})
		
		archIndepCriteria.appendChild ( __createXMLElement ("criterion", attrs = {"test_ref" : __createTest("arch", "all"), "comment" : "all architecture"}))
		#Build packages section only if we have more then one package
		if len (data["all"]) > 1:
			packageCriteria = __createXMLElement ("criteria", attrs={"comment" : "Packages section", "operator" : "OR"})
			archIndepCriteria.appendChild (packageCriteria)
		else:
			packageCriteria = archIndepCriteria
			
		for pkg in data["all"].keys():
			packageCriteria.appendChild ( __createXMLElement ("criterion", attrs = {"test_ref" : __createDPKGTest(pkg, data["all"][pkg]), "comment" : "%s DPKG is earlier than %s" % (pkg, data["all"][pkg])}))
	
		archCriteria.appendChild (archIndepCriteria)

	# Optimize packages tree in 2 stages
	diff = differ ()
	for i in range(2):
		
		if i == 0:
			dsaData = data
		else:
			dsaData = diff.getDiffer()
		
		diff.Clean()	
		for (key, value) in dsaData.iteritems():
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
					supportedArchCriteria.appendChild ( __createXMLElement ("criterion", attrs = {"test_ref" : __createTest("arch", arch), "comment" : "%s architecture" % arch}))
					archDependCriteria.appendChild (supportedArchCriteria)
		
			packageCriteria = __createXMLElement ("criteria", attrs={"comment" : "Packages section", "operator" : "OR"})
			for bpkg in eq.keys():
				packageCriteria.appendChild ( __createXMLElement ("criterion", attrs = {"test_ref" : __createDPKGTest(bpkg, eq[bpkg]), "comment" : "%s DPKG is earlier than %s" % (bpkg, eq[bpkg])}))
			
			if len(diff.getArchs()) != releaseArchHash[release]:			
				archDependCriteria.appendChild (packageCriteria)
				archCriteria.appendChild (archDependCriteria)
			else:
				archCriteria.appendChild (packageCriteria)
		
	# Generate XML for all other packages
	if len(di):
		archDependCriteria = __createXMLElement ("criteria", attrs={"comment" : "Architecture depended section", "operator" : "AND"})
			
		for (key, value) in di.iteritems():
			supportedPlatformCriteria = __createXMLElement ("criteria", attrs={"comment" : "Supported platform section", "operator" : "AND"})
			supportedPlatformCriteria.appendChild ( __createXMLElement ("criterion", attrs = {"test_ref" : __createTest("arch", key), "comment" : "%s architecture" % key}))
		
			packageCriteria = __createXMLElement ("criteria", attrs={"comment" : "Packages section", "operator" : "OR"})
					
			for bpkg in di[key].keys():
				packageCriteria.appendChild ( __createXMLElement ("criterion", attrs = {"test_ref" : __createDPKGTest(bpkg, di[key][bpkg]), "comment" : "%s DPKG is earlier than %s" % (bpkg, di[key][bpkg])}))
				supportedPlatformCriteria.appendChild (packageCriteria)
		
		archDependCriteria.appendChild (supportedPlatformCriteria)
		archCriteria.appendChild (archDependCriteria)	
		 	
	softwareCriteria.appendChild (archCriteria)	
	
	return (softwareCriteria)

def createDefinition (dsa, dsaref):
	""" Generate OVAL header of Definition tag
	
		Print general informaton about OVAL definition. Use createPlatformDefinition for generate criteria 
		sections for each affected release.
		
		Argument keywords:
		dsa -- DSA dentificator
		dsaref -- DSA parsed data
	"""	
	if not dsaref.has_key("release"):
		logging.log(logging.ERROR, "DSA %s: Release definition not well formatted. Ignore this DSA." % dsa)
		raise DSAFormatException
		
	if not dsaref.has_key("packages"):
		logging.log(logging.ERROR, "DSA %s: Package information missed. Ignore this DSA." % dsa)
		raise DSAFormatException

	if not dsaref.has_key("description"):
		logging.log(logging.WARNING, "DSA %s: Description information missed." % dsa)
		dsaref["description"] = ""

	if not dsaref.has_key("moreinfo"):
		logging.log(logging.WARNING, "DSA %s: Moreinfo information missed." % dsa)
		dsaref["moreinfo"] = ""
	
	if not dsaref.has_key("secrefs"):
		logging.log(logging.WARNING, "DSA %s: Secrefs information missed." % dsa)
		dsaref["secrefs"] = ""

	doc = xml.dom.minidom.Document ()
	
	### Definition block: Metadata, Notes, Criteria
	### TODO: Replace DSA id with unique id
	definition = __createXMLElement ("definition", attrs = {"id" : "oval:org.debian:def:%s" % __trimzero(dsa), "version" : "1", "class" : "vulnerability"})
	
	### Definition : Metadata : title, affected, reference, description ###
	metadata = __createXMLElement ("metadata")
	metadata.appendChild (__createXMLElement ("title", dsaref["description"]))

	### Definition : Metadata : Affected : platform, product ###
	affected = __createXMLElement ("affected", attrs = {"family" : "unix"})
	for platform in dsaref["release"]:
		affected.appendChild ( __createXMLElement ("platform", "Debian GNU/Linux %s" % platform))
	affected.appendChild ( __createXMLElement ("product", dsaref.get("packages")))
		
	metadata.appendChild (affected)
	### Definition : Metadata : Affected : END ###

	refpatern = re.compile (r'((CVE|CAN)-[\d-]+)')
	for ref in dsaref.get("secrefs").split(" "):
		result = refpatern.search(ref)
		if result:
			(ref_id, source) = result.groups()
			metadata.appendChild ( __createXMLElement ("reference", attrs = {"source" : source, "ref_id" : ref_id, "ref_url" : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=%s" % ref_id}) )
	
	#TODO: move this info to other place
	metadata.appendChild ( __createXMLElement ("description", "What information can i put there?"))
	debianMetadata = __createXMLElement ("debian")
	if dsaref.has_key("date"):
		debianMetadata.appendChild ( __createXMLElement ("date", dsaref["date"]) )
	debianMetadata.appendChild ( __createXMLElement ("moreinfo", dsaref["moreinfo"]) )
	metadata.appendChild (debianMetadata)
	definition.appendChild ( metadata )

	### Definition : Criteria ###
	if len(dsaref["release"]) > 1:
		#f we have more than one release - generate additional criteria section
		platformCriteria = __createXMLElement ("criteria", attrs = {"comment" : "Platform section", "operator" : "OR"})
		definition.appendChild (platformCriteria)
	else:
		platformCriteria = definition
	
	for platform in dsaref["release"]:
		data = dsaref["release"][platform]
		platformCriteria.appendChild (createPlatformDefinition(platform, data, dsa))
		
	### Definition : Criteria END ###

	return (definition)

def createOVALDefinitions (dsaref):
	""" Generate XML OVAL definition tree for range of DSA
	
		Generate namespace section and use other functions to generate definitions,
		tests, objects and states subsections.
		
		return -- Generated OVAL XML definition 
	"""
	doc = xml.dom.minidom.Document ()

	root = __createXMLElement ("oval_definitions", 
			attrs= {
				"xsi:schemaLocation" : "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd",
				"xmlns:xsi" 		: "http://www.w3.org/2001/XMLSchema-instance",
				"xmlns:ind-def " 	: "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent",
				"xmlns:linux-def" : "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
				"xmlns:oval-def" : "http://oval.mitre.org/XMLSchema/oval-definitions-5",
				"xmlns:unix-def" : "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix",
				"xmlns" 				: "http://oval.mitre.org/XMLSchema/oval-definitions-5",
				"xmlns:oval" 		: "http://oval.mitre.org/XMLSchema/oval-common-5"
			}
			)
	doc.appendChild (root)
	root.appendChild ( __createGeneratorHeader () )
	
	definitions = doc.createElement ("definitions")
	
	keyids = dsaref.keys()
	keyids.sort()
	for dsa in keyids:
		try:
			definitions.appendChild (createDefinition(dsa, dsaref[dsa]))
		except DSAFormatException:
			logging.log (logging.ERROR, "DSA %s: Bad data file. Ignore this DSA." % dsa)
			
	root.appendChild (definitions)
	
	root.appendChild(tests)
	root.appendChild(objects)
	root.appendChild(states)

	return doc

def printOVALDefinitions (doc):
	if doc.getElementsByTagName("definitions")[0].hasChildNodes():
		xml.dom.ext.PrettyPrint(doc)
