rem http://msdn.microsoft.com/en-us/library/windows/desktop/ms680687.aspx

if exist D:\Traveler\. set MyRoot=D:\Traveler
if exist C:\Opt\. set MyRoot=C:\Opt
if "%MyRoot%"=="" set MyRoot=C:

md %MyRoot%\My
md %MyRoot%\My\DbgHelp

setx DBGHELP_DBGOUT 1
setx DBGHELP_LOG %MyRoot%\My\DbgHelp\DbgHelpLog.txt

pause
