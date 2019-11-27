from burp import IBurpExtender
from burp import IScannerInsertionPointProvider
from burp import IScannerInsertionPoint
from burp import IParameter
import string

class BurpExtender(IBurpExtender,IScannerInsertionPointProvider):
    def registerExtenderCallbacks(callbacks):
        self._helpers=callbacks.getHelpers()
        callbacks.setExtensionName("input scan insertion point")
        callbacks.registerScannerInsertionPointProvider(self)
        
        return

    def getInsertionPoints(baseRequestResponse):

        dataParameter=self._helpers.getRequestParameter(baseRequestResponse.getRequest(),"data")
        if dataParameter is None:
            return None
        else:
            return [ InsertionPoint(self._helpers,baseRequestResponse.getResponse(),dataParameter.getValue()) ]




class InsertionPoint(IScannerInsertionPoint):

    def __init__(self,helpers,baseRequest,dataParameter):
        self._helpers=helpers
        self._baseRequest=baseRequest
        dataParameter=helpers.bytesToString()

    def getInsertionPointName():
        pass

    def getBaseValue():
        pass

    def buildRequest(payload):
        pass

    def getPayloadOffsets(payload):
        pass

    def getInsertionPointType():
        pass







