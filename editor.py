from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from java.io import PrintWriter

class BurpExtender(IBurpExtender,IMessageEditorTabFactory):

    def registerExtenderCallbacks(self,callbacks):
        self._callbacks=callbacks
        self._helpers=callbacks.getHelpers()
        callbacks.setExtensionName("Serialized input editor")
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self,controller,editable):
        return Base64InputTab(self,controller,editable)


class Base64InputTab(IMessageEditorTab):
    def __init__(self,extender,controller,editable):
        self._extender=extender
        self._editable=editable

        self._txtInput=extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)

        self._stdout=PrintWriter(extender._callbacks.getStdout(),True)

    def getTabCaption(self):
        return "Serialized input"

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self,content,isRequest):
        return isRequest

    def setMessage(self,content,isRequest):
        if content is None:
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        else:
            # self._stdout.println(self._extender._helpers.bytesToString(content))
            parameter=self._extender._helpers.getRequestParameter(content,"word")
            self._txtInput.setText(self._extender._helpers.base64Decode(self._extender._helpers.urlDecode(parameter.getValue())))
            self._txtInput.setEditable(self._editable)

        self._currentMessage=content

    def getMessage(self):
        if self._txtInput.isTextModified():
            text=self._txtInput.getText()
            input=self._extender._helpers.urlEncode(self._extender._helpers.base64Encode(text))
            return self._extender._helpers.updateParameter(self._currentMessage,self._extender._helpers.buildParameter("word",input,IParameter.PARAM_BODY))
        else:
            return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()