from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JLabel, JCheckBox, JRadioButton, ButtonGroup, JButton, JTextArea, JScrollPane, JFileChooser, UIManager, JTextField
import javax.swing.filechooser as filechooser
import json, urllib, os, time

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    requestCount = 0
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("Blind XSS Injector")
        self._callbacks.addSuiteTab(self)
        self.helpers = self._callbacks.getHelpers()
        self._callbacks.registerHttpListener(self)
        self.load_default_settings()

    def getTabCaption(self):
        return "Blind XSS Injector"
    
    def checkbox_changed(self, event):
        checkbox = event.getSource()
        index = int(checkbox.getText())

        if checkbox.isSelected():
            self.paramCheckboxes[index] = True
        else:
            self.paramCheckboxes[index] = False
        
    def getUiComponent(self):
        x = y = 20

        # preset parameter types, used when no default config is found
        self.paramCheckboxes = [True, True, False, False, False, False, False]
        
        self.panel = JPanel()
        self.panel.setLayout(None)

        self.label1 = JLabel("Payloads:")
        self.label1.setBounds(x, y, 80, 20)
        self.panel.add(self.label1)
        self.submittedPayloads = JTextArea()
        self.scrollPane1 = JScrollPane(self.submittedPayloads)
        self.scrollPane1.setBounds(x, y + 30, 300, 300)
        self.panel.add(self.scrollPane1)

        self.label2 = JLabel("Headers:")
        self.label2.setBounds(x + 320, y, 80, 20)
        self.panel.add(self.label2)
        self.submittedHeaders = JTextArea()
        self.scrollPane2 = JScrollPane(self.submittedHeaders)
        self.scrollPane2.setBounds(x + 320, y + 30, 300, 300)
        self.panel.add(self.scrollPane2)

        self.injectHeaders = JCheckBox()
        self.injectHeaders.setBounds(x + 650, y, 20, 20)
        self.panel.add(self.injectHeaders)
        self.label3 = JLabel("Inject headers")
        self.label3.setBounds(x + 675, y, 200, 20)
        self.panel.add(self.label3)

        self.injectParameters = JCheckBox()
        self.injectParameters.setBounds(x + 650, y + 30, 20, 20)
        self.panel.add(self.injectParameters)
        self.label4 = JLabel("Inject parameters")
        self.label4.setBounds(x + 675, y + 30, 200, 20)
        self.panel.add(self.label4)

        self.label5 = JLabel("If an entered header isn't already in the base request:")
        self.label5.setBounds(x + 650, y + 75, 400, 20)
        self.panel.add(self.label5)
        self.customHeaders = JRadioButton("Add header")
        self.customHeaders.setBounds(x + 650, y + 105, 150, 20)
        self.onlyExistingHeaders = JRadioButton("Only use existing headers")
        self.onlyExistingHeaders.setBounds(x + 850, y + 105, 220, 20)
        self.buttonGroup1 = ButtonGroup()
        self.buttonGroup1.add(self.customHeaders)
        self.buttonGroup1.add(self.onlyExistingHeaders)
        self.panel.add(self.customHeaders)
        self.panel.add(self.onlyExistingHeaders)

        self.label6 = JLabel("Override/extend the values of the headers with the payloads:")
        self.label6.setBounds(x + 650, y + 150, 350, 20)
        self.panel.add(self.label6)
        self.overwriteHeaders = JRadioButton("Override values")
        self.overwriteHeaders.setBounds(x + 650, y + 180, 150, 20)
        self.addToHeaders = JRadioButton("Extend values")
        self.addToHeaders.setBounds(x + 850, y + 180, 150, 20)
        self.buttonGroup1 = ButtonGroup()
        self.buttonGroup1.add(self.overwriteHeaders)
        self.buttonGroup1.add(self.addToHeaders)
        self.panel.add(self.overwriteHeaders)
        self.panel.add(self.addToHeaders)

        self.save = JButton("Save", actionPerformed=self.save_settings)
        self.save.setBounds(x, y + 350, 100, 30)
        self.panel.add(self.save)
        self.load = JButton("Load", actionPerformed=self.load_settings)
        self.load.setBounds(x + 120, y + 350, 100, 30)
        self.panel.add(self.load)

        self.label7 = JLabel("In-scope requests from the Proxy are scanned")
        self.label7.setBounds(x, y + 400, 300, 20)
        self.panel.add(self.label7)
        self.label8 = JLabel("Per payload, a new request is made for each header or parameter")
        self.label8.setBounds(x, y + 420, 500, 20)
        self.panel.add(self.label8)

        self.label9 = JLabel("Perform injections on the following parameter types:")
        self.label9.setBounds(x + 650, y + 225, 350, 20)
        self.panel.add(self.label9)

        self.paramURL = JCheckBox("0", actionPerformed=self.checkbox_changed)
        self.paramURL.setBounds(x + 650, y + 255, 20, 20)
        self.panel.add(self.paramURL)
        self.label10 = JLabel("URL parameter")
        self.label10.setBounds(x + 675, y + 255, 200, 20)
        self.panel.add(self.label10)

        self.paramBody = JCheckBox("1", actionPerformed=self.checkbox_changed)
        self.paramBody.setBounds(x + 650, y + 285, 20, 20)
        self.panel.add(self.paramBody)
        self.label11 = JLabel("Body parameter")
        self.label11.setBounds(x + 675, y + 285, 200, 20)
        self.panel.add(self.label11)

        self.paramCookie = JCheckBox("2", actionPerformed=self.checkbox_changed)
        self.paramCookie.setBounds(x + 650, y + 315, 20, 20)
        self.panel.add(self.paramCookie)
        self.label12 = JLabel("Cookie parameter")
        self.label12.setBounds(x + 675, y + 315, 200, 20)
        self.panel.add(self.label12)

        self.paramXML = JCheckBox("3", actionPerformed=self.checkbox_changed)
        self.paramXML.setBounds(x + 650, y + 345, 20, 20)
        self.panel.add(self.paramXML)
        self.label13 = JLabel("XML parameter")
        self.label13.setBounds(x + 675, y + 345, 200, 20)
        self.panel.add(self.label13)

        self.paramXMLTag = JCheckBox("4", actionPerformed=self.checkbox_changed)
        self.paramXMLTag.setBounds(x + 850, y + 255, 20, 20)
        self.panel.add(self.paramXMLTag)
        self.label14 = JLabel("XML tag attribute parameter")
        self.label14.setBounds(x + 875, y + 255, 200, 20)
        self.panel.add(self.label14)

        self.paramMultipart = JCheckBox("5", actionPerformed=self.checkbox_changed)
        self.paramMultipart.setBounds(x + 850, y + 285, 20, 20)
        self.panel.add(self.paramMultipart)
        self.label15 = JLabel("Multipart attribute parameter")
        self.label15.setBounds(x + 875, y + 285, 200, 20)
        self.panel.add(self.label15)

        self.paramJSON = JCheckBox("6", actionPerformed=self.checkbox_changed)
        self.paramJSON.setBounds(x + 850, y + 315, 20, 20)
        self.panel.add(self.paramJSON)
        self.label16 = JLabel("JSON parameter")
        self.label16.setBounds(x + 875, y + 315, 200, 20)
        self.panel.add(self.label16)

        self.label17 = JLabel("Encoding:")
        self.label17.setBounds(x + 650, y + 390, 150, 20)
        self.panel.add(self.label17)
        self.encodeHeaders = JCheckBox()
        self.encodeHeaders.setBounds(x + 650, y + 420, 20, 20)
        self.label21 = JLabel("Encode header injections")
        self.label21.setBounds(x + 675, y + 420, 200, 20)
        self.panel.add(self.label21)
        self.panel.add(self.encodeHeaders)
        self.encodeParams = JCheckBox()
        self.encodeParams.setBounds(x + 650, y + 450, 20, 20)
        self.label18 = JLabel("Encode parameter injections")
        self.label18.setBounds(x + 675, y + 450, 200, 20)
        self.panel.add(self.label18)
        self.panel.add(self.encodeParams)

        self.label19 = JLabel("Max. requests per second:")
        self.label19.setBounds(x + 850, y + 30, 200, 20)
        self.panel.add(self.label19)
        self.requestThrottle = JTextField('10')
        self.requestThrottle.setBounds(x + 1005, y + 25, 50, 30)
        self.panel.add(self.requestThrottle)

        self.repeaterRequests = JCheckBox()
        self.repeaterRequests.setBounds(x + 850, y, 20, 20)
        self.panel.add(self.repeaterRequests)
        self.label20 = JLabel("Use Repeater requests")
        self.label20.setBounds(x + 875, y, 200, 20)
        self.panel.add(self.label20)

        # settings dict, used for saving/loading
        self.settings = {
            "Payloads": self.submittedPayloads,
            "Headers": self.submittedHeaders,
            "Checkboxes": {
                "injectHeaders": self.injectHeaders,
                "injectParameters": self.injectParameters,
                "repeaterRequests": self.repeaterRequests,
                "customHeaders": self.customHeaders,
                "onlyExistingHeaders": self.onlyExistingHeaders,
                "overwriteHeaders": self.overwriteHeaders,
                "addToHeaders": self.addToHeaders,
                "paramURL": self.paramURL,
                "paramBody": self.paramBody,
                "paramCookie": self.paramCookie,
                "paramXML": self.paramXML,
                "paramXMLTag": self.paramXMLTag,
                "paramMultipart": self.paramMultipart,
                "paramJSON": self.paramJSON,
                "encodeParams": self.encodeParams,
                "encodeHeaders": self.encodeHeaders                
            },
            "requestThrottle": self.requestThrottle
        }

        return self.panel
    
    def load_default_settings(self):
        path = os.path.join(os.getcwd(), 'default.json')
        if os.path.exists(path):
            print('Default settings loaded from: {}'.format(path))
            with open(path) as f:
                config = json.loads(f.read())

            self.settings["Payloads"].setText('\n'.join(config["Payloads"]))
            self.settings["Headers"].setText('\n'.join(config["Headers"]))
            self.settings["requestThrottle"].setText(config["requestThrottle"])

            for key, value in self.settings["Checkboxes"].items():
                value.setSelected(config["Checkboxes"][key])

            # update set param types
            for i in range(len(self.paramCheckboxes)):
                disposition = ["paramURL", "paramBody", "paramCookie", "paramXML", "paramXMLTag", "paramMultipart", "paramJSON"]
                self.paramCheckboxes[i] = config["Checkboxes"][disposition[i]]

        # preset checkboxes, used when no default config is found
        else:
            self.customHeaders.setSelected(True)
            self.addToHeaders.setSelected(True)
            self.paramURL.setSelected(True)
            self.paramBody.setSelected(True)
            self.encodeParams.setSelected(True)
            print('Default settings not found. Save your config in "{}" to use as default settings.'.format(path))
            
    def save_settings(self, event):
        config = {}
        config["Payloads"] = self.settings["Payloads"].getText().split('\n')
        config["Headers"] = self.settings["Headers"].getText().split('\n')
        config["requestThrottle"] = self.settings["requestThrottle"].getText()

        config["Checkboxes"] = {}
        for key, value in self.settings["Checkboxes"].items():
            config["Checkboxes"][key] = value.isSelected()

        fileChooser = JFileChooser()
        fileFilter = filechooser.FileNameExtensionFilter("json", ['json'])
        fileChooser.setFileFilter(fileFilter)

        result = fileChooser.showSaveDialog(None)
        if result == JFileChooser.APPROVE_OPTION:
            choosenFile = fileChooser.getSelectedFile().getAbsolutePath()
            path, extensie = os.path.splitext(choosenFile)
            path += '.json'

            with open(path, "w") as f:
                f.write(json.dumps(config))

            print('Settings saved to: {}'.format(path))

    def load_settings(self, event):
        fileChooser = JFileChooser()
        fileFilter = filechooser.FileNameExtensionFilter("json", ['json'])
        fileChooser.setFileFilter(fileFilter)
        
        result = fileChooser.showOpenDialog(None)
        if result == JFileChooser.APPROVE_OPTION:
            choosenFile = fileChooser.getSelectedFile()
            path = choosenFile.getAbsolutePath()
            with open(path) as f:
                config = json.loads(f.read())

            self.settings["Payloads"].setText('\n'.join(config["Payloads"]))
            self.settings["Headers"].setText('\n'.join(config["Headers"]))
            self.settings["requestThrottle"].setText(config["requestThrottle"])

            for key, value in self.settings["Checkboxes"].items():
                value.setSelected(config["Checkboxes"][key])

            # update set param types
            for i in range(len(self.paramCheckboxes)):
                disposition = ["paramURL", "paramBody", "paramCookie", "paramXML", "paramXMLTag", "paramMultipart", "paramJSON"]
                self.paramCheckboxes[i] = config["Checkboxes"][disposition[i]]

            print('Settings loaded from: {}'.format(path))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.injectParameters.isSelected() and not self.injectHeaders.isSelected():
            return
        if not messageIsRequest:
            return
        if toolFlag != self._callbacks.TOOL_PROXY:
            if toolFlag == self._callbacks.TOOL_REPEATER and self.repeaterRequests.isSelected():
                pass
            else:
                return
        
        request = messageInfo.getRequest()
        requestInfo = self.helpers.analyzeRequest(messageInfo)
        url = requestInfo.getUrl()

        if not self._callbacks.isInScope(url):
            return
        
        # extract info from base request
        https = 1 if 'https' in requestInfo.url.getProtocol() else 0
        host = requestInfo.url.getHost()
        port = requestInfo.url.port
        parameters = requestInfo.getParameters()
        headers = requestInfo.getHeaders()
        body = request[requestInfo.getBodyOffset():]

        # user-defined payloads and headers
        payloads = [p for p in self.submittedPayloads.getText().split("\n") if p != "" and not p.isspace()]
        if len(payloads) == 0:
            return
        if self.encodeHeaders.isSelected or self.encodeParams.isSelected():
            encodedPayloads = [urllib.quote(p) for p in payloads]
        submittedHeaders = [h for h in self.submittedHeaders.getText().split("\n") if h != "" and not h.isspace()]

        # inject headers
        if self.injectHeaders.isSelected() and submittedHeaders:
            if self.encodeHeaders.isSelected():
                self.make_request_headers(encodedPayloads, submittedHeaders, headers, body, host, port, https)
            else:
                self.make_request_headers(payloads, submittedHeaders, headers, body, host, port, https)

        # inject parameters
        if self.injectParameters.isSelected() and parameters:
            selectedParameters = []
            for parameter in parameters:
                ptype = parameter.getType()
                if self.paramCheckboxes[ptype]:
                    selectedParameters.append(parameter)

            if self.encodeParams.isSelected():
                self.make_request_parameters(request, selectedParameters, encodedPayloads, host, port, https)
            else:
                self.make_request_parameters(request, selectedParameters, payloads, host, port, https)

    def make_request_headers(self, payloads, submittedHeaders, headers, body, host, port, https):
        for submittedHeader in submittedHeaders:
            found = False
            for i in range(len(headers)):

                # entered header is already in base request
                if headers[i].split(':')[0] == submittedHeader:

                    # overwrite header value with payload
                    if self.overwriteHeaders.isSelected(): 
                        for payload in payloads:
                            if self.requestCount == int(self.requestThrottle.getText()):
                                time.sleep(1)
                                self.requestCount = 0
                            tempHeaders = headers[:]
                            tempHeaders[i] = '{}: {}'.format(submittedHeader, payload)
                            newRequest = self.helpers.buildHttpMessage(tempHeaders, body)
                            self._callbacks.makeHttpRequest(host, port , https, newRequest)
                            self.requestCount += 1
                            found = True

                    # extend header value with payload
                    else: 
                        for payload in payloads:
                            if self.requestCount == int(self.requestThrottle.getText()):
                                time.sleep(1)
                                self.requestCount = 0
                            tempHeaders = headers[:]
                            tempHeaders[i] += payload
                            newRequest = self.helpers.buildHttpMessage(tempHeaders, body)
                            self._callbacks.makeHttpRequest(host, port , https, newRequest)
                            self.requestCount += 1
                            found = True

            # entered header isn't already in base request
            if not found and self.customHeaders.isSelected(): 
                for payload in payloads:
                    if self.requestCount == int(self.requestThrottle.getText()):
                        time.sleep(1)
                        self.requestCount = 0
                    tempHeaders = headers[:]
                    tempHeaders.add('{}: {}'.format(submittedHeader, payload))
                    newRequest = self.helpers.buildHttpMessage(tempHeaders, body)
                    self._callbacks.makeHttpRequest(host, port, https, newRequest)
                    self.requestCount += 1

    def make_request_parameters(self, request, parameters, payloads, host, port, https):
        for parameter in parameters:
            name = parameter.getName()
            ptype = parameter.getType()

            for payload in payloads:
                if self.requestCount == int(self.requestThrottle.getText()):
                    time.sleep(1)
                    self.requestCount = 0
                newParameter = self.helpers.buildParameter(name, payload, ptype)
                newRequest = self.helpers.updateParameter(request, newParameter)
                self._callbacks.makeHttpRequest(host, port, https, newRequest)
                self.requestCount += 1