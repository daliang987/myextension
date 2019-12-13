from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.io import PrintWriter
from array import array
import time

GREP_STRING = "<%="
GREP_STRING_BYTES = bytearray(GREP_STRING)


BACKUP_FILE_PAYLOADS=['.bak','.zip','.rar','.tar','.gz','.tar.gz','.bz2','.bz','.back','.backup']


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
        callbacks.setExtensionName("Backup File")

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
        

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        print 'active scan'

        if insertionPoint.getInsertionPointName()!="BackupFile":
            return

        for PAYLOAD in BACKUP_FILE_PAYLOADS:
            BACKEXT = bytearray(PAYLOAD)
            # make a request containing our injection test in the insertion point
            checkRequest = insertionPoint.buildRequest(BACKEXT)
            print self._helpers.bytesToString(checkRequest)
            try:
                checkRequestResponse=self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest)

                statusCode = checkRequestResponse.getResponse().getStatusCode()

                if statusCode>=300:
                    return


                # get the offsets of the payload within the request, for in-UI highlighting
                requestHighlights = [insertionPoint.getPayloadOffsets(BACKEXT)]

                # report the issue
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(checkRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, None)],
                    "Backup File Found",
                    "Backup File Found By Extension"+ BACKEXT,
                    "High")]
            except Exception,e:
                # report the issue
                self._stderr.println(str(e))

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
