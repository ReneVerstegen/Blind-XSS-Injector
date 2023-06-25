# Blind XSS Injector
This Burp Suite plugin is able to perform blind XSS injections on headers and parameters of HTTP requests. Use in addition to your callback platform to automatically test for blind XSS vulnerabilities.

## Features
- Search for different types of parameters to perform injections
- Add new headers with payloads to requests
- Extend or override values of existing headers with your payloads

## Installation
- Make sure the [Jython standalone JAR](https://www.jython.org/download) is set as the Python environment in the Burp Extender settings
- Add **Blind_XSS_Injector.py** to your Burp extensions
- To use the default settings, add **default.json** to the same folder as the .py file.

## How to use
- Add your target to the scope
- Select **Inject headers** and/or **Inject parameters**
- While browsing trough the application, the traffic from the Proxy is scanned for headers/parameters to perform injections
- If needed, select **Use Repeater requests** to scan these too

## Settings
- In the plugin tab, add payloads using the url from your callback server like [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express) or [ezXSS](https://github.com/ssl/ezXSS)
- Add headers the extension should look for
- The extension will generate a lot of traffic, a thottle can be set to limit this
- Choose whether non-existing headers should be used
- Choose whether to extend or override header values
- Select the parameter types the extensions should look for
- Enable/disable URL-encoding for the injections
- To overwrite the default settings, save as default.json

## Screenshots
![Screenshot](/Images/Screenshot.png)