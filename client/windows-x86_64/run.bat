certutil -addstore root "%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer"
.\mitmproxy\mitmdump.exe -q -s ..\proxy.py --set listen_port=8080
pause