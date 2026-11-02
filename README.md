Title: Avalue avalueio.sys physical byte access

Vendor: Avalue Technology Inc.
Product: AvalueIO
Component: avalueio.sys
SHA-256: a5a4a3c3d3d5a79f3ed703fc56d45011c21f9913001fcbcc43a3f7572cff44ec
MD5: 1da1cfe6aa15325c9ecf8f8c9b2cd12d
SHA-1: b406920634361f4b7d7c1ec3b11bb40872d85105
Size: 14512 bytes
PE timestamp: 2016-03-25 09:41:25 UTC
FileVersion: 2.00.02.00
ProductVersion: 2.00.02.00
OriginalFilename: AVALUEIO.SYS
Version-resource product name: AvalueIO
Signer: CN=Avalue Technology Inc., OU=Digital ID Class 3 - Microsoft Software Validation v2, O=Avalue Technology Inc., L=TAIWAN, S=TAIWAN, C=TW
Certificate thumbprint: 40222B8E912202FAEA680E50F8615B3396A6B9AF
Certificate not before: 2013-08-21 00:00:00 UTC
Certificate not after: 2016-08-20 23:59:59 UTC
Authenticode status: Valid
Device: \\.\AvalueIODev
PDB: c:\drv_work\avalue\drivers\avalueio_v202\sys\objfre_win7_amd64\amd64\avalueio.pdb

CVE:

Description:
avalueio.sys in Avalue Technology Inc. AvalueIO FileVersion 2.00.02.00 (SHA-256 a5a4a3c3d3d5a79f3ed703fc56d45011c21f9913001fcbcc43a3f7572cff44ec) passes a caller-supplied 32-bit physical address to MmMapIoSpace on IOCTL 0x9C40A44C (METHOD_BUFFERED), maps a fixed length of one byte as non-cached, does not validate the address, and stores one caller-supplied byte there, which allows a local user to write one byte of physical memory via \\.\AvalueIODev. IOCTL 0x9C40640C reads one byte from the same address. The Authenticode status is Valid, signed by Avalue Technology Inc. On 2026-11-02, on an isolated Windows 10 virtual machine, an administrator loaded this file and the service started. The administrator locked one of its own pages at physical address 0xab90e000, wrote 0x3C as the first byte, and did not send either IOCTL. Local account aida-low, a member of Users and not a member of Administrators, opened \\.\AvalueIODev, sent IOCTL 0x9C40640C, and read 0x3C. That account then sent IOCTL 0x9C40A44C, wrote 0x5A, and read 0x5A back through IOCTL 0x9C40640C, then wrote 0xA5 and read 0xA5 back the same way. The administrator read the first byte of that physical page and saw 0x5A, then 0xA5. The test did not show a crash. The device security descriptor was O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC). Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA.

Suggested fix: on IOCTL 0x9C40A44C and IOCTL 0x9C40640C, use only a physical address chosen inside the driver, and limit access to \\.\AvalueIODev to Administrators and SYSTEM.
