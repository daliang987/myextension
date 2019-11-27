from burp import IBurpExtender
from burp import IScannerInsertionPointProvider
from burp import IScannerInsertionPoint
from burp import IParameter
import string

class BurpExtender(IBurpExtender, IScannerInsertionPointProvider):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Scan Base Insertion")
        
        # register ourselves as a scanner insertion point provider
        callbacks.registerScannerInsertionPointProvider(self)
        
        return
        
    # 
    # implement IScannerInsertionPointProvider
    #
    
    def getInsertionPoints(self, baseRequestResponse):
        
        # retrieve the data parameter
        requestInfo=self._helpers.analyzeRequest(baseRequestResponse)
        allParameters=requestInfo.getParameters()

        insertPoints=[]

        for parameter in allParameters:
            if parameter.getType()==IParameter.PARAM_COOKIE:
                continue
            insertPoints.append(InsertionPoint(self._helpers, baseRequestResponse.getRequest(), parameter))

        return insertPoints
# 
# class implementing IScannerInsertionPoint
#

class InsertionPoint(IScannerInsertionPoint):

    def __init__(self, helpers, baseRequest, parameter):
        self._helpers = helpers
        self._baseRequest = baseRequest
        self._parameter = parameter
        return
        
    # 
    # implement IScannerInsertionPoint
    #
    
    def getInsertionPointName(self):
        return "BaseInsertion"

    def getBaseValue(self):
        return self._parameter.getValue()

    def buildRequest(self, payload):
        newParameValue=''
        if self._parameter.getType()==IParameter.PARAM_URL:
            newParameValue=self._parameter.getValue()+self._helpers.bytesToString(self._helpers.urlEncode(payload))
        else:
            newParameValue=self._parameter.getValue()+self._helpers.bytesToString(payload)

        print newParameValue
        
        # update the request with the new parameter value
        return self._helpers.updateParameter(self._baseRequest, self._helpers.buildParameter(self._parameter.getName(), newParameValue, self._parameter.getType()))

    def getPayloadOffsets(self, payload):
        # since the payload is being inserted into a serialized data structure, there aren't any offsets 
        # into the request where the payload literally appears
        return None

    def getInsertionPointType(self):
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED