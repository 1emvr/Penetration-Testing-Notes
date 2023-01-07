Hyper-V Admins could easily create a clone of the DC and mount the VDI/VHDX.

Upon deleteing a VM, `vmms.exe` attempts to restore the original file permissions of the
corresponding .vhdx file and does so as NT AUTHORITY/SYSTEM without impersonating
the user. WE can delete the .vhdx file and create a native hard link to point this file
to a protected SYSTEM file, which we will have full permissions to.

If the operating system is vulnerable to CVE-2018-0952 or CVE-2019-0841, we can leverage
this to gain SYSTEM privileges. Otherwise, we can try to take advantage of an application
on the server that has installed a service running in the context of SYSTEM.

### Target File

An example of this is Firefox, which installs the `Mozilla Maintenance Service`. We can update
this PoC to grant our current user full permissions on the file below:
https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1

```
C:\Program Files (x86)\Mozilla Maintenancce Service\maintenanceservice.exe
takeown /F C:\Program Files (x86)\Mozilla Maintenancce Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```

