from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
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
from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import JButton
from java.awt import BorderLayout

from threading import Lock
import re

host='devxjy.xinbeiting.com'
Cookie='Cookie: JSESSIONID=4db5e904-b1a3-4d6c-8339-c9dba7fe828b'
reobj=r'^/websocket/\d+$'
extract_file=['']


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Test Auth | Cookie Repalce ")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # user jpanel add compenents
        
        self._panel=JPanel()
        self._panel.setLayout(BorderLayout())

        subpanel=JPanel()
        button =JButton("OK")
        subpanel.add(button)
    

        self._panel.add(subpanel,BorderLayout.NORTH)

        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        self._panel.add(self._splitpane,BorderLayout.CENTER)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        # callbacks.customizeUiComponent(logTable)
        # callbacks.customizeUiComponent(scrollPane)
        # callbacks.customizeUiComponent(tabs)

        callbacks.customizeUiComponent(self._panel)
        callbacks.customizeUiComponent(subpanel)
        # callbacks.customizeUiComponent(button)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Auth Test"
    
    def getUiComponent(self):
        return self._panel
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return

        if messageInfo.getHttpService().getHost()!=host:
            return 
        
        if toolFlag==4:
            bytesRequest=messageInfo.getRequest()
            requestInfo=self._helpers.analyzeRequest(messageInfo.getHttpService(),bytesRequest)
            bytesRequestBody=bytesRequest[requestInfo.getBodyOffset():]

            file = requestInfo.getUrl().getFile()

            if file in extract_file or re.match(reobj,file):
                return

            path=requestInfo.getUrl().getPath()

            if '.' in path:
                ext = path.split('.')[-1]
            else:
                ext = ''

            if ext  in ["jpg","png","gif","ico","mp4","js","css","map","html"]:
                return

            headers=requestInfo.getHeaders()
            newHeaders=[]
            for header in headers:
                if header.startswith("Cookie:"):
                    newHeaders.append(Cookie)
                else:
                    newHeaders.append(header)
                
            
            bytesNewRequest=self._helpers.buildHttpMessage(newHeaders,bytesRequestBody)
            
            newRequestResponse=self._callbacks.makeHttpRequest(messageInfo.getHttpService(),bytesNewRequest)
            

            responseInfo=self._helpers.analyzeResponse(newRequestResponse.getResponse())

            # if abs(len(newRequestResponse.getResponse())-len(messageInfo.getResponse()))>500:
            #     return


            # create a new log entry with the message details
            self._lock.acquire()
            row = self._log.size()

            log_entry=LogEntry(toolFlag, 
                requestInfo.getMethod(),
                self._callbacks.saveBuffersToTempFiles(newRequestResponse), 
                responseInfo.getStatusCode(),
                self._helpers.analyzeRequest(messageInfo).getUrl())
            
            self._log.add(log_entry)
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
        return 4

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "Method"
        if columnIndex == 2:
            return "Status"
        if columnIndex == 3:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._method
        if columnIndex == 2:
            return logEntry._status
        if columnIndex == 3:
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
    def __init__(self, tool,method, requestResponse,status, url):
        self._tool = tool
        self._method=method
        self._requestResponse = requestResponse
        self._status=status
        self._url = url
