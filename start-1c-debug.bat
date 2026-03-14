@echo off
echo Starting 1C:Enterprise with debug agent on port 1550...
echo.
echo After 1C starts, open VS Code and press F5 to attach debugger.
echo.
"C:\Program Files\1cv8\8.3.27.1859\bin\1cv8.exe" ENTERPRISE /S"KOMPUTER\TestDB" /N"a.terletskiy@sodru.com" /P"Alex80Alex" /Debug -http -port 1550
