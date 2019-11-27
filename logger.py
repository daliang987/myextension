from burp import IBurpExtender
from burp import ITab
from burp import IProxyListener
from burp import IMessageEditorController
from burp import IBurpExtenderCallbacks
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import time
import threading

sql_time=open(r'D:\HackTool\dict\sql_time.txt')

class BurpExtender(IBurpExtender, ITab, IProxyListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Custom Scan Logger")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerProxyListener(self)
        
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Logger"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IHttpListener
    #
    
    def processProxyMessage(self, messageIsRequest, message):
        # only process requests
        if not messageIsRequest:
            return

        print 'proxy'

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
        
        allParameters=requestInfo.getParameters()
        newRequestString=''
        allThreads=[]
        for param in allParameters:
            for line in sql_time.readlines():
                checkString=line.rstrip()
                end=param.getValueEnd()
                requestString=self._helpers.bytesToString(baseRequest)
                requset_prefix=requestString[:end]
                request_suffix=requestString[end:]
                newRequestString=requset_prefix+self._helpers.urlEncode(checkString)+request_suffix
                
               
                t=MyThread(func=self._callbacks.makeHttpRequest,args=(httpRequestResponse.getHttpService(),self._helpers.stringToBytes(newRequestString)))
                t.setDaemon(True)
                allThreads.append(t)


        for t in allThreads:
            t.start()
            
            
        
        for t in allThreads:
            t.join(10)

            # create a new log entry with the message details
            self._lock.acquire()
            newRequestBytes=self._helpers.stringToBytes(newRequestString)
            row = self._log.size()
            if t.get_result():
                self._log.add(LogEntry(IBurpExtenderCallbacks.TOOL_SCANNER, self._callbacks.saveBuffersToTempFiles(t.get_result()), self._helpers.analyzeRequest(t.get_result()).getUrl()))
            else:
                self._log.add(LogEntry(IBurpExtenderCallbacks.TOOL_PROXY, self._callbacks.saveBuffersToTempFiles(httpRequestResponse), self._helpers.analyzeRequest(httpRequestResponse.getHttpService(),newRequestBytes).getUrl()))
            self.fireTableRowsInserted(row, row)
            self._lock.release()


    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url



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