from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

# hard-coded payloads
# [in reality, you would use an extension for something cleverer than this]

PAYLOADS = []
payload_file=r'D:\upload_test\txt\pass.txt'

file=open(payload_file)

for line in file.readlines():
    PAYLOADS.append(bytearray(line.strip()))



class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):

    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Password payloads")
        
        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        

    #
    # implement IIntruderPayloadGeneratorFactory
    #
    
    def getGeneratorName(self):
        return "Password payloads"

    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        return IntruderPayloadGenerator()

#
# class to generate payloads from a simple list
#

class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self._payloadIndex = 0

    def hasMorePayloads(self):
        return self._payloadIndex < len(PAYLOADS)

    def getNextPayload(self, baseValue):
        payload = PAYLOADS[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1

        return payload

    def reset(self):
        self._payloadIndex = 0