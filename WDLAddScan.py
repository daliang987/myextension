from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerCheck
from burp import IScanQueueItem
from java.io import PrintWriter
import time
import threading

class BurpExtender(IBurpExtender,IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        
        self._callbacks=callbacks
        self._helpers=callbacks.getHelpers()

        self._stdout = PrintWriter(callbacks.getStdout(), True)

        self._scanQueueItems=[]
        self._reqInfos=[]

        callbacks.setExtensionName("WDL Add Scan")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag==4 and messageIsRequest:
            bytesRequest=messageInfo.getRequest()
            # self._stdout.println(self._helpers.bytesToString(bytesRequest))

            useHttps=False
            host=messageInfo.getHttpService().getHost()
            port=messageInfo.getHttpService().getPort()
            if port==443:
                useHttps=True
            
            newRequestInfo=self._helpers.analyzeRequest(messageInfo)

            path=newRequestInfo.getUrl().getPath()
            if '.' in path:
                ext = path.split('.')[-1]
            else:
                ext = ''

            if ext  in ["jpg","png","gif","ico","mp4","js","css"]:
                return

            newRequest=MyRequest(newRequestInfo)
            
            if len(self._reqInfos)==0:
                self._reqInfos.append(newRequestInfo)
                scanQueueItem = self._callbacks.doActiveScan(host, port, useHttps, bytesRequest)
                self._scanQueueItems.append(scanQueueItem)

            
            hasSameReq=False
            for reqInfo in self._reqInfos:
                if newRequest.isSameRequest(reqInfo)==True:
                    hasSameReq=True
                    break
                
            if hasSameReq==False:
                self._reqInfos.append(newRequestInfo)
                scanQueueItem = self._callbacks.doActiveScan(host, port, useHttps, bytesRequest)
                self._scanQueueItems.append(scanQueueItem)   

class MyRequest():

    def __init__(self,newRequestInfo):
        self._newRequestInfo=newRequestInfo

    def isSameRequest(self,baseRequestInfo):
        if baseRequestInfo is None:
            return False

        newRequestInfo=self._newRequestInfo

        if newRequestInfo.getMethod()!=baseRequestInfo.getMethod():
            return False


        newUrl=newRequestInfo.getUrl()
        baseUrl=baseRequestInfo.getUrl()

        if newUrl.getHost()!=baseUrl.getHost():
            return False
        if newUrl.getPort()!=baseUrl.getPort():
            return False
        if newUrl.getPath()!=baseUrl.getPath():
            return False
        
        baseParameters=baseRequestInfo.getParameters()
        newParameters=baseRequestInfo.getParameters()


        basePnames=set()
        newPnames=set()

        for bparam in baseParameters:
            if bparam.getType()!=2 and bparam.getType()!=4: # no cookie and xml attr
                # print bparam.getName()
                basePnames.add(bparam.getName())

        for nparam in newParameters:
            if nparam.getType()!=2 and nparam.getType()!=4:
                # print nparam.getName()
                newPnames.add(nparam.getName())
        
        
        print basePnames
        print newPnames
        print basePnames==newPnames        

        if basePnames==newPnames:
            return True
        
        return False

        


        

