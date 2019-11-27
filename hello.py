from burp import IBurpExtender
from java.io import PrintWriter
from java.lang import RuntimeException

class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self,callbacks):
        callbacks.setExtensionName("hello world extension")
        
        stdout=PrintWriter(callbacks.getStdout(),True)
        stderr=PrintWriter(callbacks.getStderr(),True)

        stdout.println("hello world")
        stderr.println("hello error")

        callbacks.issueAlert("hello alert")

        raise RuntimeException("hello exception")