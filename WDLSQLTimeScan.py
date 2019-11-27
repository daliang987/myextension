from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.io import PrintWriter
from array import array
import time

GREP_STRING = " your SQL syntax;"
GREP_STRING_BYTES = bytearray(GREP_STRING)

SQL_TIME_FILE=r"D:\HackTool\dict\sql_time.txt"
SQL_TIME_PAYLOADS=[]


class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # set our extension name
        callbacks.setExtensionName("SQLI By Time")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)


    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
        # print 'passive scan'
        # look for matches of our passive check grep string
        matches = self._get_matches(baseRequestResponse.getResponse(), GREP_STRING_BYTES)
        if (len(matches) == 0):
            return None

        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
            "SQL synax error",
            "The response contains the string: " + GREP_STRING,
            "Medium")]

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        print 'active scan'
        file=open(SQL_TIME_FILE)
        for line in file.readlines():
            SQL_TIME_PAYLOADS.append(line.rstrip())

        for PAYLOAD in SQL_TIME_PAYLOADS:
            SQLI_TEST = bytearray(PAYLOAD)
            # make a request containing our injection test in the insertion point
            checkRequest = insertionPoint.buildRequest(SQLI_TEST)
            # print self._helpers.bytesToString(checkRequest)
            try:
                start_time=time.time()
                checkRequestResponse=self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest)
                end_time=time.time()
                spend_time = end_time-start_time
            
                print spend_time
                # print t.get_result()
                if spend_time<5:
                    continue
                
                start_time2=time.time()
                baseRequestResponse2=self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),self._helpers.stringToBytes(insertionPoint.getBaseValue()))
                end_time2=time.time()
                spend_time2=end_time2-start_time2


                if spend_time2-spend_time<3:
                    continue

                # get the offsets of the payload within the request, for in-UI highlighting
                requestHighlights = [insertionPoint.getPayloadOffsets(SQLI_TEST)]

                # report the issue
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(checkRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, None)],
                    "SQL injection",
                    "SQL Inject By Time Sleep: " + PAYLOAD + ", The request spend time:"+str(spend_time),
                    "High")]
            except Exception,e:
                # report the issue
                self._stderr.println(str(e))
            finally:
                file.close()

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0


#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
