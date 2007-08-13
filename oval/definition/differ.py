import logging
from copy import deepcopy

class differ:
    """Class to matching (package) (arch, version) hashes"""
    
    __equal = {}
    __differ = {}
    __equalArch = []
 
    def __init__ (self):
        pass
    
    def __dictAdd (self, dic, pkey, key, value):
        if dic.has_key (pkey):
            dic[pkey][key] = value
        else:
            dic[pkey] = {key : value}
    def Clean (self):
        self.__equal = {}
        self.__differ = {}
        self.__equalArch = []
        
    def getEqual (self):
        return (self.__equal)
    
    def getDiffer(self):
        return (self.__differ)
    
    def getArchs(self):
        return (self.__equalArch)
    
    def Init (self, architecture, packages):
        self.__equalArch = [architecture, ]
        self.__equal = packages
        self.__differ  = {}

    def compareElement (self, architecture, packages):
        #We already inspected this arch
        if architecture in self.__equalArch:
            logging.log(logging.DEBUG, "Architecture " + architecture + "already inspected")
            return (0)
        
        #We don't have inspected base
        if len(self.__equal) == 0:
            self.Init(architecture, packages)
            return (0)
        
        equalC = deepcopy(self.getEqual())
        differC = deepcopy(self.getDiffer())
            
        for package in packages.keys():
            if package in equalC.keys():
                if packages[package] != equalC[package]:
                    self.__dictAdd(differC, architecture, package, packages[package])
                    for arch in self.__equalArch:
                        self.__dictAdd (differC, arch, package, equalC[package])
                    del (equalC[package])
            else:
                #New package that not present in qeual dictionary 
                self.__dictAdd (differC, architecture, package, packages[package])
        
        #Compare equals dictionary with packages of given architecture
        for package in equalC.keys():
            if not package in packages.keys():
                for arch in self.__equalArch:
                    self.__dictAdd (differC, arch, package, equalC[package])
                del (equalC[package])
        
        if len(self.getEqual()) - len(equalC) <= len(self.getEqual())/4:
            self.__equalArch.append(architecture)
            self.__equal = equalC
            self.__differ = differC
        else:
            logging.log(logging.DEBUG, "Architecture " + architecture + " too differens")
            self.__differ[architecture]  = packages
        return (1)
