from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IScannerListener
from burp import IExtensionStateListener
from java.io import PrintWriter

import os



class BurpExtender(IBurpExtender,IHttpListener):
    
    def registerExtenderCallbacks(self,callbacks):
        
        self._callbacks=callbacks

        callbacks.setExtensionName("my http listener")

        self._stdout=PrintWriter(callbacks.getStdout(),True)

        callbacks.registerHttpListener(self)

        self._helpers=callbacks.getHelpers()
        

    def processHttpMessage(self,toolFlag,messageIsRequest,messageInfo):
        self._stdout.println("from module:"+self._callbacks.getToolName(toolFlag))
        if messageIsRequest:
            self._stdout.println("this is request")
            requestInfo=self._helpers.analyzeRequest(messageInfo.getRequest())
            
            self._stdout.println(type(requestInfo.getHeaders()))
            for header in requestInfo.getHeaders():
                self._stdout.println(header)

        else:
            self._stdout.println("this is response")
            self._stdout.println(type(messageInfo.getResponse()))
            self._stdout.println(self._helpers.bytesToString(messageInfo.getResponse()).encode('utf-8'))


        
        
    