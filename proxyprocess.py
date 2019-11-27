from burp import IBurpExtender
from burp import IProxyListener
from java.io import PrintWriter
import time
import threading

sql_time=open(r'D:\HackTool\dict\sql_time.txt')

class BurpExtender(IBurpExtender,IProxyListener):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("sql time delay check")
        
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)


        # register ourselves as a Proxy listener
        callbacks.registerProxyListener(self)
        

    
    #
    # implement IProxyListener
    #

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            httpRequestResponse=message.getMessageInfo()
            baseRequest=httpRequestResponse.getRequest()
            requestInfo= self._helpers.analyzeRequest(httpRequestResponse)
            reqUrl=requestInfo.getUrl()
            reqPath=reqUrl.getPath()
            resource_ext=['js','gif','jpg','png','css','ico']
            

            if reqPath.rfind(".")!=-1: 
                file_ext=reqPath[reqPath.rfind(".")+1:] # get the path extension
                if file_ext in resource_ext:
                    return
            
            print reqPath
            allParameters=requestInfo.getParameters()
            for param in allParameters:
                for line in sql_time.readlines():
                    checkString=line.rstrip()
                    end=param.getValueEnd()
                    requestString=self._helpers.bytesToString(baseRequest)
                    requset_prefix=requestString[:end]
                    request_suffix=requestString[end:]
                    newRequestString=requset_prefix+self._helpers.urlEncode(checkString)+request_suffix
                    
                    # print param.getName()+'='+param.getValue()
                    # self._stdout.println(newRequestString)
                    print (self._helpers.analyzeRequest(httpRequestResponse.getHttpService(), self._helpers.stringToBytes(newRequestString)).getUrl()).getFile()
                    start_time=time.time()
                    t=MyThread(func=self._callbacks.makeHttpRequest,args=(httpRequestResponse.getHttpService(),self._helpers.stringToBytes(newRequestString)))
                    t.setDaemon(True)
                    t.start()
                    t.join(10)
                    end_time=time.time()

                    spend_time=end_time-start_time

                    self._stdout.println(spend_time)

                    if spend_time<5:
                        continue
                    else:
                        checkRequestResponse=t.get_result()
                        responseString=''
                        if checkRequestResponse is not None:
                            responseString=self._helpers.bytesToString(checkRequestResponse.getResponse())
                        else:
                            responseString='time out ,response is not recieve'
                        
                    file_name=time.strftime("%Y-%m-%d", time.localtime()) + ".txt"
                    print file_name
                    result=open('D:\\temp\\result\\'+file_name,'a')
                    result.write("spend_time:"+str(spend_time)+'\n')
                    result.write(newRequestString)
                    result.close()
        # self._stdout.println(
        #     ("Proxy request to " if messageIsRequest else "Proxy response from ") +
        #     message.getMessageInfo().getHttpService().toString())


class MyThread(threading.Thread):
    def __init__(self, func, args):
        super(MyThread, self).__init__()
        self.func = func
        self.args = args

    def run(self):
        self.result = self.func(*self.args)

    def get_result(self):
        try:
            return self.result
        except Exception:
            return None