# SharpWebClientScanner
C# tool that verifies the status of WebClient services across multiple targets in the domain. \
This small project is designed to assess the running state of the Web Client service (WebDAV) on a remote system by examining the existence of the DAV RPC SERVICE named pipe.\
Admin privileges are not necessary on the remote system, but valid credentials (no anonymous access) are required.\
This version has the ability to get computer list from the Active Directory or Text file, so would be better suited for scanning a large number of computers.
## Usage
Scan WebClient using LDAP:
```
SharpWebClientScanner.exe --domain lab.local --output output.txt
```
Scan WebClient using computer list:
```
SharpWebClientScanner.exe --file computers.txt --output output.txt
```
## Reference
* https://github.com/G0ldenGunSec/GetWebDAVStatus
