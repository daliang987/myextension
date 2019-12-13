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
        callbacks.setExtensionName("Backup File Insertion")
        
        # register ourselves as a scanner insertion point provider
        callbacks.registerScannerInsertionPointProvider(self)
        
        return
        
    # 
    # implement IScannerInsertionPointProvider
    #
    
    def getInsertionPoints(self, baseRequestResponse):
        
        # retrieve the data parameter
        requestInfo=self._helpers.analyzeRequest(baseRequestResponse)

    
        requestUrl=requestInfo.getUrl()
        requestPath=requestUrl.getPath()


        if '.' not in requestPath:
            return


        requestHeaders=requestInfo.getHeaders()

        insertPoints=[]
        

        insertPoints.append(InsertionPoint(self._helpers, baseRequestResponse.getRequest(), requestPath))

        return insertPoints
# 
# class implementing IScannerInsertionPoint
#

class InsertionPoint(IScannerInsertionPoint):

    def __init__(self, helpers, baseRequest, path):
        self._helpers = helpers
        self._baseRequest = baseRequest
        self._path = path
        return
        
    # 
    # implement IScannerInsertionPoint
    #
    
    def getInsertionPointName(self):
        return "BackupFile"

    def getBaseValue(self):
        return self._path

    def buildRequest(self, payload):
        
        if not self._helpers.bytesToString(payload).startswith("."):
            

        ext=self._path.split('.')[-1]
        
        reqinfo=self._helpers.analyzeRequest(self._baseRequest)
        headers=reqinfo.getHeaders()
        headers.pop(0)
        # print headers
        newHeader="GET "+self._path+"."+self._helpers.bytesToString(payload)+" HTTP/1.1"
        headers.insert(0,newHeader)
        # print headers

        newHeadersString=''
        for header in headers:
            newHeadersString+=header+'\r\n'
        
        newHeadersString+="\r\n"

        print newHeadersString

        self._headerString=newHeadersString

        self._bytesRequest=self._helpers.stringToBytes(newHeadersString)

        return self._bytesRequest
    

    def getPayloadOffsets(self, payload):
        # since the payload is being inserted into a serialized data structure, there aren't any offsets 
        # into the request where the payload literally appears
        strpayload=self._helpers.bytesToString(payload)
        lenpayload=len(strpayload)
        payload_index=self._headerString.find(strpayload)
        if payload_index==-1:
            return
        
        return [payload_index,payload_index+lenpayload]

    def getInsertionPointType(self):
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED