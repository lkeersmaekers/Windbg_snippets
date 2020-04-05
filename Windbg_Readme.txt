vim:fdc=5:fdm=marker:fmr={{{{,}}}}:foldlevel=1:ft=vim

" => Readme/Setup {{{{1
"   => from http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-Building-your-USB-thumbdrive {{{{2

-------------------------------------------------------------------------------------------------------
Command file                | Comment
-------------------------------------------------------------------------------------------------------
Symbols.cmd                 | Environmentvariabelen instellen & folders aanmaken om symbos te gebruiken
DbgHelp_Logging.cmd         | IF having issues with using symbols ->Turn logging on
DbgEng_Bang_Analyze_Off.cmd | Opening debugger runs !analyze by default. Turn it off
Windbg_AeDebug.reg          | Post mortem debugger instellen
WinDbg_IA.reg               | Post mortem debugger instellen
Note: procdump -ma -i c:\dumps -> instellen van post mortem debugger om een dumpfile te schrijven.
-------------------------------------------------------------------------------------------------------

-----------------------------------------------------------------------------------------------------------------------------------------
Folder               | original installer                                            | Comments
-----------------------------------------------------------------------------------------------------------------------------------------
debuggers            | installers\Debugging Tools for Windows\dbg_amd64.msi          | Installatiefolder \debuggers is Microsoft Standard
debuggers_x86        | installers\Debugging Tools for Windows\dbg_x86.msi            | Andrew Richards default voor x86
application_verifier | installers\Application Verifier\ApplicationVerifier.amd64.msi | Enkel 64 bit nodig
performance_toolkit  | installers\Windows Performance Toolkit\wpt_x64.msi            | Enkel 64 bit nodig
-----------------------------------------------------------------------------------------------------------------------------------------

"   => cmdtree {{{{2
http://voneinem-windbg.blogspot.co.uk/2008/09/amazing-helper-cmdtree.html
http://blogs.msdn.com/b/debuggingtoolbox/archive/2008/09/17/special-command-execute-commands-from-a-customized-user-interface-with-cmdtree.aspx

.cmdtree cmdtree.txt

"   => vim {{{{2
Interessante filetypes om dumps in vim te bekijken.
  set ft=flexwiki
  set ft=reva
  set ft=gitrebase

" => Howto's livekd/kd/cdb {{{{1"
" => How to dump all function names of an executable? {{{{2
" http://stackoverflow.com/questions/36064314/how-to-dump-all-function-names-of-an-executable
cdb -z "c:\windows\system32\notepad.exe" -c ".symfix;.reload;x *!*;q"

" => How to dump a function in an executable? {{{{2
" http://stackoverflow.com/a/42692346/52598
c:\my\debuggers\cdb -c ".fnent user32!InternalDialogbox;q" c:\my\debuggers\cdb
c:\my\debuggers_x86\cdb -c ".fnent user32!InternalDialogbox;q" c:\my\debuggers_x86\cdb

" => How to execute command/script against multiple dumps? {{{{2
" https://www.wintellect.com/automating-analyzing-tons-of-minidump-files-with-windbg-and-powershell/
$folder = "c:\dumps"
gci $folder -Recurse | % { cdb -z $_.fullname -c "!gle -all;q" }
gci $folder -Recurse | % {$dmp = $_.fullname;cdb -z $dmp -c "!load pde;!dpx;kbnf;q" | % { "$($dmp) - $($_)" }}

" => How to execute command/script against multiple processes? {{{{2
" Get last error
gps ul3comm | % { c:\my\debuggers_x86\cdb -p $_.ID -c "!gle -all;qd" } | out-file gle.log -encoding ascii
" Sets forkerNumberOfBiSecondsAfterWhichWorkerThatFailedToSendKeepAliveMessageIsToBeForciblyTerminated from 300 (10 minutes) to 600 (20 minutes)
gps afc | % {c:\my\debuggers_x86\cdb -p $_.ID -c "db 004C81C0 L3;ed 4c81c1 0258;db 004C81C0 L3;qd" | sls '004C81C0'}

" => How to dump 100 calls from a running process {{{{2
" http://stackoverflow.com/questions/38710710/how-to-prevent-the-output-truncated-if-the-rows-of-output-from-the-windbg-to-lar
cdb -c "tc 100;q" calc >> foo.txt

" => How to dump all calls from a process {{{{2
cdb -c ".while (1) {tc;r}" msg.exe * /time:999999 Test >> foo.txt
cdb -c ".while (1) {tc;r}" <executable> <params> >> foo.txt

" => How to add a breakpoint on postmessage and dump the parameters using a script file {{{{2
$script = 'PostmessageBreakpoint.script'
'bm USER32!PostmessageA "r rsi, rdi, r8, r9;g"' | Out-File $script -Encoding Ascii -Force
'.cls'                                          | Out-File $script -Encoding Ascii -Append -Force
'g;'                                            | Out-File $script -Encoding Ascii -Append -Force
gps powershell_ise | % { c:\apps\my\debuggers\cdb -p $_.ID -cfr PostmessageBreakpoint.script }

" => How to add breakpoints and dumps for ul3acc/afc {{{{2
<#
gci d:\ul3acc\userbackup\kelie\debug\*.log -recurse | where lastwritetime -gt (get-date).AddHours(-10) | sls 'Creating'
gci d:\ul3acc\userbackup\kelie\debug\*.log -recurse | where lastwritetime -gt (get-date).AddHours(-10) | sls '^Breakpoint' | group -Property line, filename -NoElement | ft -a
#>

$root = "D:\ul3acc\userBackup\kelie\debug\$((Get-Date).ToString('yyyyMMdd'))-SIM-HTTP500" # no spaces
if (!(Test-Path $root)) {New-Item $root -ItemType Directory -Force}
$escapedRoot = $root -replace '\\', '\\'

$afcScript = "$($root)\afc.script"
$ul3script = "$($root)\ul3.script"

# afc script
@'
    ***** Disable Break on Exception
    * Disable all first/second chance exception handling (https://stackoverflow.com/a/28308973/52598).
    .foreach(exc {sx}) {.catch{sxd ${exc}}}

    ***** Show Timestamps
    * Turns on the display of time stamp information.
    .echotimestamps 1'

    ***** Logfile
    * Send a copy of the events and commands from the Debugger Command window to a new log file.
    .logopen /t <<escapedRoot>>\\afc_trace.log

    ***** Breakpoint/Dump
    * bp    - Add a breakpoint on address 004d9af9
    * .dump - Create a dump file
    *            /mA Creates a minidump with full memory data, handle data, unloaded module information, basic memory information, and thread time information.
    *            /u  Appends the date, time, and PID to the dump file name
    * gc    - Resumes execution from the breakpoint in the same fashion that was used to hit the breakpoint
    bp 004d9af9 ".dump /mA /u <<escapedRoot>>\\afc_request_aborted.dmp;gc"

    ***** Exception/Dump
    * sx-      - Does not change the handling status or the break status of the specified exception or event.
    * -c       - Specifies a command that is executed if the exception or event occurs. This command is executed when the first chance to handle this exception occurs, regardless of whether this exception breaks into the debugger.
    * .dump    - Create a dump file
    *             /mA Creates a minidump with full memory data, handle data, unloaded module information, basic memory information, and thread time information.
    *             /u  Appends the date, time, and PID to the dump file name
    * 40080201 - The exception number that the command acts on, in the current radix
    * gc       - Resumes execution from the breakpoint in the same fashion that was used to hit the breakpoint
    sx- -c ".dump /mA /u <<escapedRoot>>\\afc_40080201.dmp;gc" 40080201

    ***** Exception/Dump
    * sx-      - Does not change the handling status or the break status of the specified exception or event.
    * -c       - Specifies a command that is executed if the exception or event occurs. This command is executed when the first chance to handle this exception occurs, regardless of whether this exception breaks into the debugger.
    * .dump    - Create a dump file
    *             /mA Creates a minidump with full memory data, handle data, unloaded module information, basic memory information, and thread time information.
    *             /u  Appends the date, time, and PID to the dump file name
    * 80010108 - The exception number that the command acts on, in the current radix
    * gc       - Resumes execution from the breakpoint in the same fashion that was used to hit the breakpoint
    sx- -c ".dump /mA /u <<escapedRoot>>\\afc_80010108.dmp;gc" 80010108

    ***** Breakpoint/Exception status/Go
    * bl - List existing breakpoints
    * sx - Displays the list of exceptions for the current process and the list of all nonexception events and displays the default behavior of the debugger for each exception and event.
    * g  - Start executing the process
    bl;sx;g
'@ -replace '<<escapedRoot>>', $escapedRoot | Out-File $afcScript -Encoding Ascii -Force


# ul3acc script
@'
    ***** Disable Break on Exception
    * Disable all first/second chance exception handling (https://stackoverflow.com/a/28308973/52598).
    .foreach(exc {sx}) {.catch{sxd ${exc}}}

    ***** Show Timestamps
    * Turns on the display of time stamp information.
    .echotimestamps 1'

    ***** Logfile
    * Send a copy of the events and commands from the Debugger Command window to a new log file.
    .logopen /t <<escapedRoot>>\\ul3acc_trace.log

    ***** Breakpoint/Dump
    * bp    - Add a breakpoint on address 00a1ab9d
    * .dump - Create a dump file
    *            /mA Creates a minidump with full memory data, handle data, unloaded module information, basic memory information, and thread time information.
    *            /u  Appends the date, time, and PID to the dump file name
    * gc    - Resumes execution from the breakpoint in the same fashion that was used to hit the breakpoint
    bp 00a1ab9d ".dump /ma /u <<escapedRoot>>\\ul3acc_request_aborted.dmp;gc"

    ***** Exception/Dump
    * sx-      - Does not change the handling status or the break status of the specified exception or event.
    * -c       - Specifies a command that is executed if the exception or event occurs. This command is executed when the first chance to handle this exception occurs, regardless of whether this exception breaks into the debugger.
    * .dump    - Create a dump file
    *             /mA Creates a minidump with full memory data, handle data, unloaded module information, basic memory information, and thread time information.
    *             /u  Appends the date, time, and PID to the dump file name
    * 80004035 - The exception number that the command acts on, in the current radix
    * gc       - Resumes execution from the breakpoint in the same fashion that was used to hit the breakpoint
    sx- -c ".dump /ma /u <<escapedRoot>>\\ul3acc_80004035.dmp;gc" 80004035

    ***** Event/Dump
    * sx-      - Does not change the handling status or the break status of the specified exception or event.
    * -c       - Specifies a command that is executed if the exception or event occurs. This command is executed when the first chance to handle this exception occurs, regardless of whether this exception breaks into the debugger.
    * .dump    - Create a dump file
    *             /mA Creates a minidump with full memory data, handle data, unloaded module information, basic memory information, and thread time information.
    *             /u  Appends the date, time, and PID to the dump file name
    * av       - The event that the command acts on
    * gc       - Resumes execution from the breakpoint in the same fashion that was used to hit the breakpoint
    sx- -c ".dump /ma /u <<escapedRoot>>\\ul3acc_access_violation.dmp;gc" av

    ***** Load Extension
    * Load the pde extension DLL into the debugger
    .load D:\ul3acc\userBackup\kelie\tools\debuggers_x86\winext\pde

    ***** Breakpoint/Log
    * bp        - Add a breakpoint on address 00520ad8
    * .echotime - current date/time
    * .echo     - Display a comment string
    * ~.        - The current thread
    * r         - Display registers, floating-point registers, flags, pseudo-registers, and fixed-name aliases.
    * !dpx      - Equivalent of dps, dpp, dpa and dpu (combined); also class types (dt) and trap frames (kV). Displays from stack pointer to the stack base.
    * gc        - Resumes execution from the breakpoint in the same fashion that was used to hit the breakpoint.
    bp 00520ad8 ".echotime;.echo Breakpoint 00520ad8;~.;r;!dpx;gc"

    ***** Breakpoint/Log
    * bp        - Add a breakpoint on address 004bf9f8 .if the eax register equals nil
    *             Het lijkt er op dat we op address 004bc65e een AV krijgen owv de functie call op address 004bfa2a in deze 004bf9f8 functie
    *             In de AV functie 004bc65e krijgen we in EDX een 00000000 door. Deze komt wss. van param_1 (eax) die in 004bf9f8 dan ook al 00000000 is
    *             Als deze theorie klopt, moeten we weer verder kijken waarom param_1 in 004bf9f8 nil is.
    *             NOTE: method wordt zéér veel gecalled (13.341 Breakpoint 004bf9f8, ul3acc_trace_1d20_2020-04-04_21-21-34-807.log).
    *             NOTE2: param_1 van 004bf9f8 is idd ook nil. Nog verder naar callers kijken waarom die nil doorgeven!
    *                Debugger (not debuggee) time: Sat Apr  4 13:02:52.514 2020 (UTC + 2:00)
    *                Breakpoint 004bf9f8
    *                eax=00000000 ebx=015a3280 ecx=0000002c edx=00520ad8 esi=00000000 edi=01c3d7a0 eip=004bf9f8 esp=0019d6dc ebp=0019d6f8
    * .echotime - current date/time
    * .echo     - Display a comment string
    * r         - Display registers, floating-point registers, flags, pseudo-registers, and fixed-name aliases
    * gc        - Resumes execution from the breakpoint in the same fashion that was used to hit the breakpoint.
    bp 004bf9f8 ".if (@eax = 0x00000000) {.echotime;.echo Breakpoint 004bf9f8;r eax,ebx,ecx,edx,esi,edi,eip,esp,ebp;!dpx};gc"

    ***** Breakpoint/Log
    * bp        - Add a breakpoint on address 004bc65e .if the eax register equals nil
    *             LAST_CONTROL_TRANSFER is van f685338b naar 004bc65e. f685338b is echter een adres op de heap normaal?!
    *             NOTE: method wordt zéér veel gecalled (1.312.020 Breakpoint 004bc65e, ul3acc_trace_1d20_2020-04-04_21-21-34-807.log)
    * .echotime - current date/time
    * .echo     - Display a comment string
    * r         - Display registers, floating-point registers, flags, pseudo-registers, and fixed-name aliases
    * kbnf 2    - Display the stack frame of the given thread, together with related information
    * gc        - Resumes execution from the breakpoint in the same fashion that was used to hit the breakpoint.
    bp 004bc65e ".if (@eax = 0x00000000) {.echotime;.echo Breakpoint 004bc65e;r eax,ebx,ecx,edx,esi,edi,eip,esp,ebp;!dpx};gc"

    ***** Breakpoint/Log
    * bu        - Add a deferred or unresolved breakpoint
    * .echotime - current date/time
    * .echo     - Display a comment string
    * ~.        - The current thread
    * r         - Display registers, floating-point registers, flags, pseudo-registers, and fixed-name aliases.
    * !dpx      - Equivalent of dps, dpp, dpa and dpu (combined); also class types (dt) and trap frames (kV). Displays from stack pointer to the stack base.
    * gc        - Resumes execution from the breakpoint in the same fashion that was used to hit the breakpoint.
    bm cdosys!* ".echotime;.echo Breakpoint cdosys!*;~.;r;!dpx;gc"

    ***** Breakpoint/Exception status/Go
    * bl - List existing breakpoints
    * sx - Displays the list of exceptions for the current process and the list of all nonexception events and displays the default behavior of the debugger for each exception and event.
    * g  - Start executing the process
    bl;sx;g

'@ -replace '<<escapedRoot>>', $escapedRoot | Out-File $ul3script -Encoding Ascii -Force

while ($true) {
    # Get the afc proces
    gwmi -cl win32_process -filter 'commandline like "%forker:04%"' | % {
        # test if the afc process is not being debugged already
        if (@(gwmi -cl win32_process -filter "commandline like '%-p $($_.ProcessID) -cfr%'").Count -eq 0) {
            # Attach a debugger
            $argumentlist = "-p $($_.ProcessID) -cfr $($afcScript)"
            Start-Process D:\ul3acc\userBackup\kelie\tools\debuggers_x86\cdb -ArgumentList $argumentlist
            Write-Output "$(Get-Date) - Attached to $($_.ProcessID)"
        }
    }
    # Get all ul3acc processes with parent forker:04
    gwmi -cl win32_process -filter "ParentProcessID = $((gwmi -cl win32_process -filter 'commandline like "%forker:04%"').ProcessID)" | % {
        # test if the ul3acc process is not being debugged already
        if (@(gwmi -cl win32_process -filter "commandline like '%-p $($_.ProcessID) -cfr%'").Count -eq 0) {
            # Attach a debugger
            $argumentlist = "-p $($_.ProcessID) -cfr $($ul3script)"
            Start-Process D:\ul3acc\userBackup\kelie\tools\debuggers_x86\cdb -ArgumentList $argumentlist
            Write-Output "$(Get-Date) - Attached to $($_.ProcessID)"
        }
    }
    Start-Sleep -Seconds 5
}
" => How to add a breakpoint on an address and create a dumpfile using a script file {{{{2

" => How to trace all calls from a process {{{{2
windbg calc
"skipping all the ldrint system calls
bp calc!WinMain ; g
" tracing only calc module from eip to some specific address and printing the return values (please note using arbitrary values as EndAddress may possibly corrupt the code by inserting 0xcc in middle of instruction )
wt -l 2 -oR -m calc

" => How to view stacktraces for heap allocations {{{{2
" https://stackoverflow.com/questions/24451461/is-there-a-way-to-get-userstack-for-all-heap-userptr
" Turn on Gflags -> Image File -> Create user mode stack trace database
.foreach /pS 4 /ps 3 (userptr {.shell -ci "!heap -p -all" find "busy" | find /V "*"}) { !heap -p -a ${userptr}};

" => Breakpoints: How to dump all calls from a live debugging session {{{{2
bm calc!* "k L1;g;"

bm ul3comm!* "r;!dpx;g;"
bm PDC32!* "r;!dpx;g;"
bm vbscript!* "r;!dpx;g;"

" => Breakpoints: How to enable/disable breakpoints from other breakpoints{{{{2
bm calc!* "k L1;g;"
bm ntdll!* "kv1;gc;"
bm user32!* "kv1;gc;"
bd "ntdll!*"
bd "user32!*"
bu TER21!TerCreateWindowAlt ".echotime;.echo Start TER21!TerCreateWindowAlt;be \"ntdll!*\";be \"user32!*\";gc;"
bu TER21!TerWndProc ".echotime;.echo Start TER21!TerWndProc;bd \"ntdll!*\";bd \"user32!*\";gc;"

" => Breakpoints: How to dump waits on handles {{{{2
bm ntdll!ntwaitforsingleobject "j poi(@esp+0x4)=0x010c 'kbnf 2;r;gc;';gc;"
bm ntdll!*waitforsingle* "!handle poi(@esp+0x4);gc;';gc;"
bm ntdll!*waitformultiple* "dd poi(esp + 0x8) L4;gc;';gc;"

" => Breakpoints: WinDbg: Setting a breakpoint on every EXPORTED function of a module
"    https://reverseengineering.stackexchange.com/a/18362/1680
.foreach ( place { !showexports ollydbg } ) { bp place }

" => How to get the current apartment for a thread {{{{2
" http://chenlailin.blogspot.be/2008/02/how-to-get-current-apartment-for-thread.html
!teb
dt TEB fffdd000 ReservedForOle
dt SOleTlsData 0x00f02b48
!grep pCurrentCtx dt SOleTlsData 0x00f02b48
!grep AptKind dt -r2 CObjectContext 0x00f03c58


" => How to get PID/TID in a RPC call {{{{2
kP
dx -r2 ((combase!CSyncClientCall *)<address van pClientCall>)
-> Zoek op dwPid en dwTid
" => How to get the contents of a section object {{{{2
"https://stackoverflow.com/questions/46745973/how-to-get-the-content-of-a-section-object-in-a-kernel-dump
!process 0 0 ul3comm.exe
.process /r /p fffffa800ea80060
? @$proc
?? (char *)@$proc->ImageFileName
!handle 0 7 fffffa800ea80060 Section

!object fffff8a012e26710
dt nt!_SECTION_OBJECT Segment fffff8a012e26710
dt nt!_SEGMENT u2.FirstMappedVa 0xfffff8a0102d7820
db 0x0000000003400000 L1

" => How to get the TTD calls containing lasterror/messagebox {{{{2
dx @$calls = @$cursession.TTD.Calls("kernelbase!GetLastError", "user32!MessageBoxW")
dx -g @$calls.Where(x => x.Function.Contains("MessageBox") || x.ReturnValue != 0).OrderBy(obj => obj.@"ReturnValue").OrderBy(x => x.TimeStart.Sequence), 1000

" => How to stop or trace lasterrors {{{{2
bm ntdll!RtlSetLastWin32Error ".if (poi(@esp+0x4)!=0x0) {.echotime;kbnf 2;r;gc;} .else {gc;}"
"of equivalent met j
bm ntdll!RtlSetLastWin32Error "j poi(@esp+0x4)!0x0 '.echotime;kbnf 2;r;gc;';gc;"

" => Windbg {{{{1"
" => Inside Windows Debugging {{{{2

--------------------------------------------------------------------------------
| Start a target process directly                | - windbg.exe target.exe     |
| Dynamically attach to existing process         | - windbg.exe -pn target.exe |
|                                                | - windbg.exe -p [PID]       |
| Stop debugging the target without terminating  | - qd                        |
| Stop debugging the target with terminating     | - q                         |
| -----------------------------------------------|---------------------------- |
| Dump Memory                                    | - dd, db and so on          |
| Edit Memory                                    | - ed, eb and so on          |
| Insert code breakpoints                        | - bp                        |
| Dump stack trace                               | - k, kP, kn, kvn and so on  |
--------------------------------------------------------------------------------

"   => Windows Debugging Notebook {{{{2

---------------------
Watch and trace (p39)
---------------------
- Alleen tijdens een live debug
- Toont de method calls tussen start en end address
wt =<startaddress> <endaddress>

-----------------
Disassemble (p43)
-----------------
u @eip       - disassemble from @eip
ub @eip L8   - disassemble backwards from @eip
uf @eip      - disassemble the entire function @eip is currently in (finds start & end automatically)
uf /c @eip   - view the calls made by the function

-------------------------------------
Display information from memory (p93)
-------------------------------------
db @ebp l10  - view 16 bytes starting from @ebp as bytes and ascci
dc @ebp l10  - view 16 bytes starting from @ebp as double words and ascci

------------------------------------
Dump alle strings op de stack (p103)
------------------------------------
!teb
? poi(@$teb+0x10) -> Controleer of overeenkomt met Stacklimit (+0x08 voor 32bit)
? poi(@$teb+0x08) -> Controleer of overeenkomt met StackBase  (+0x04 voor 32bit)

64bit
dpa esp poi(@$teb+0x08) -> Dumpt alle strings op de stack (gebruik dpu voor unicode)
dps esp poi(@$teb+0x08) -> Dumpt alle method calls op de stack (kan ook gebruikt worden indien stack corrupt is)
dpp esp poi(@$teb+0x08) -> Dumpt alle pointers die gerefereerd worden vanuit de stack.

32bit
dpa esp poi(@$teb+0x04) -> Dumpt alle strings op de stack (gebruik dpu voor unicode)
dps esp poi(@$teb+0x04) -> Dumpt alle method calls op de stack (kan ook gebruikt worden indien stack corrupt is)
dpp esp poi(@$teb+0x04) -> Dumpt alle pointers die gerefereerd worden vanuit de stack.


----------------------------------------------------
Displaying all symbols for a specified module (p125)
----------------------------------------------------
x /t /v /n notepad!*

"   => Procdump Extensions (you want this!!!) {{{{2

.load D:\Traveler\My\Andrew Richards\ProcDumpExt v6.4\x64\ProcDumpExt.dll
.load D:\Traveler\My\Andrew Richards\ProcDumpExt v6.4\x86\ProcDumpExt.dll

!ProcDumpExt.help
!ProcDumpExt.dpx

"   => CMKD Extensions (you want this!!!) {{{{2

.load cmkd.dll

!cmkd.help

!stack
The !stack command displays registers based parameters passed to x64 functions.

"   => Delphi Objecten Windbg Scripts {{{{2
------------------------------------------------------------------------------------------------------
Find the base address en base of code for a module(executable)
https://stackoverflow.com/questions/38205106/resolve-address-of-accessviolation-in-the-map-file
------------------------------------------------------------------------------------------------------
De addressen in een .map file + image base address + base of code zijn deze die in de stacktrace (kvnf) getoond worden.
Usually the load address of a process is $400000 (the actual value is defined in the Project Options and is $400000 by default), but that may be different at runtime due to various reasons, such as re-basing.
Once you determine the actual load address, you need to include the actual offset of the code segment within the process.
That offset is usually $1000 (the actual value is defined in the compiled executable's PE header).
So, to map a memory address at runtime to an address in the .map file, you usually subtract $401000 from the runtime memory address. Values may be different!

!dh <module> -f

dc /c 1 esp ebp                           View stack frame cfr Delphi CPU window
dds ebp                                   View stack frame. Top address is EBP of next stack frame. dss <address> will walk the stack.
s -d 0x00000000 L?0xffffffff 30c5bf9c     Find 30c5bf9c in memory (search)
s -a 0x00000000 L?0xffffffff "TList"      Find TList in memory (search)

-------------------------------------
Find a classname from a stack pointer
-------------------------------------
da poi(poi(poi(poi(0018f4bc)))-38)+1 L16  TList
dW poi(poi(poi(poi(0018f4bc)))-38)+1 L16  TList...

  Breakdown
  ---------
  dd 0018f4bc                          is a stack pointer
  dd poi(0018f4bc)                     Pointer to the variable FList  (01e8a270)
  dd poi(poi(0018f4bc))                Pointer to the instance FList  (00427d38)
  dW poi(poi(poi(0018f4bc)))           Pointer to the classtype TList (00432c20)
  da poi(poi(poi(poi(0018f4bc)))-38)+1 Points to the non-Unicode string returned by TObject.ClassName, internally known as Self.vmtClassName.

  Dereference and dump 400 (1600/4) stack pointers
  starting from 0x0018f4bc
  (Use -38 for Delphi XE2. Use -2c for Delphi 7)
  ----------------------------------------------
r? @$t0 = @esp
r? @$t19 = 0x2c
.for (r @$t1 = 0; @$t1 < 1600; r @$t1 = @$t1 + 4) { .catch { .printf "stackpointer: %p -- instance: %p -- class: ", @$t0 + @$t1, poi(poi(poi(@$t0 + @$t1))); da poi(poi(poi(poi(@$t0 + @$t1)))-@$t19)+1 } }

-------------------
VMT Layout Delphi 7
-------------------
{ Virtual method table entries }

  vmtSelfPtr           = -76;
  vmtIntfTable         = -72;
  vmtAutoTable         = -68;
  vmtInitTable         = -64;
  vmtTypeInfo          = -60;
  vmtFieldTable        = -56;
  vmtMethodTable       = -52;
  vmtDynamicTable      = -48;
  vmtClassName         = -44;
  vmtInstanceSize      = -40;
  vmtParent            = -36;
  vmtSafeCallException = -32 deprecated;  // don't use these constants.
  vmtAfterConstruction = -28 deprecated;  // use VMTOFFSET in asm code instead
  vmtBeforeDestruction = -24 deprecated;
  vmtDispatch          = -20 deprecated;
  vmtDefaultHandler    = -16 deprecated;
  vmtNewInstance       = -12 deprecated;
  vmtFreeInstance      = -8 deprecated;
  vmtDestroy           = -4 deprecated;

  vmtQueryInterface    = 0 deprecated;
  vmtAddRef            = 4 deprecated;
  vmtRelease           = 8 deprecated;
  vmtCreateObject      = 12 deprecated;

----------------------------------------------------------------
http://marc.durdin.net/2011/12/windbg-and-delphi-exceptions.html
----------------------------------------------------------------
When debugging a Delphi XE2 app in WinDBG, NTSD or a related debugger, it is very helpful to be able to display the actual
class name and error message from an exception in the debugger.  The following script will do that for you automatically:

Delphi XE2 : sxe -c "da poi(poi(poi(ebp+1c))-38)+1 L16;du /c 100 poi(poi(ebp+1c)+4)" 0EEDFADE
Delphi 7   : sxe -c "da poi(poi(poi(ebp+1c))-2c)+1 L16;da /c 100 poi(poi(ebp+1c)+4)" 0EEDFADE

----------------------------------------------------------------------
http://marc.durdin.net/2012/08/locating-delphi-exceptions-in-live.html
----------------------------------------------------------------------
The following WinDbg command will return a list of all Delphi exception records located within the stacks of each thread in the process
Delphi XE2 : ~*e s -d poi(@$teb+8) poi(@$teb+4) 0EEDFADE

If you just wanted to do the current thread, you would run:
Delphi XE2 : s -d poi(@$teb+8) poi(@$teb+4) 0EEDFADE

-----------------------------------------------------------------------
  adhv Type information kunnen we globals raadplegen
-----------------------------------------------------------------------
  .formats rtl70!SysutilsDecimalSeparator      - 0x4007668f
  .formats poi(rtl70!SysutilsDecimalSeparator) - (2c) , => Decimalseparator is comma

-----------------------------------------------------------------------
http://marc.durdin.net/2012/05/windbg-and-delphi-exceptions-in-x64.html
-----------------------------------------------------------------------
TODO: READ

"   => Writing LINQ queries in WinDbg {{{{2
----------------------------------------------------------------------------------
https://blogs.msdn.microsoft.com/windbg/2016/10/03/writing-linq-queries-in-windbg/
----------------------------------------------------------------------------------
dx Debugger

=> Equivalent of !busy command using LINQ - https://stackoverflow.com/a/54237138/52598
dx     @$curprocess.Threads.Select(p=>p.Stack).Select(p=>p.Frames).Select(t=>t[1]).Where((p=>p.ToDisplayString().Contains("Wait")!=true)).Where(p=>p.ToDisplayString().Contains("Remove")!=true)

"   => Javascript Scripting {{{{2
----------------------------------------------------------------------------------
https://msdn.microsoft.com/library/windows/hardware/3442E2C4-4054-4698-B7FB-8FE19D26C171.aspx
https://msdn.microsoft.com/library/windows/hardware/F477430B-10C7-4039-9C5F-25556C306643.aspx
https://msdn.microsoft.com/library/windows/hardware/A8E12564-D083-43A7-920E-22C4D627FEE8.aspx
----------------------------------------------------------------------------------

" => Defrag Tools {{{{1
"   => Defrag Tools: #9 - ProcDump  {{{{2

-r parameter !!!

ProcDump v6.00 - Writes process dump files
Copyright (C) 2009-2013 Mark Russinovich
Sysinternals - www.sysinternals.com
With contributions from Andrew Richards

Monitors a process and writes a dump file when the process exceeds the
specified criteria or has an exception.

usage: procdump [-64] [[-c|-cl CPU usage] [-u] [-s seconds]] [-n exceeds] [-e [1 [-b] [-f <filter,...>] [-g]]] [-h] [-l] [-m|-ml commit usage] [-ma | -mp] [-o] [-p|-pl counter threshold] [-r] [-t] [-d <callback DLL>] <[-w] <process name or service name or PID> [dump file] | -i <dump file> | -x <dump file> <image file> [arguments] >

   -64     By default ProcDump will capture a 32-bit dump of a 32-bit process
           when running on 64-bit Windows. This option overrides to create a
           64-bit dump.
   -b      Treat debug breakpoints as exceptions (otherwise ignore them).
   -c      CPU threshold above which to create a dump of the process.
   -cl     CPU threshold below which to create a dump of the process.
   -d      Invoke the minidump callback routine named MiniDumpCallbackRoutine
           of the specified DLL.
   -e      Write a dump when the process encounters an unhandled exception.
           Include the 1 to create dump on first chance exceptions.
   -f      Filter the first chance exceptions. Wildcards (*) are supported.
           To just display the names without dumping, use a blank ("") filter.
   -g      Only capture native exceptions in a managed process (no interop).
   -h      Write dump if process has a hung window (does not respond to
           window messages for at least 5 seconds).
   -i      Install ProcDump as the AeDebug postmortem debugger.
           Only -ma, -mp and -d are supported as options.
   -l      Display the debug string logging of the process.
   -m      Memory commit threshold in MB at which to create a dump of the
           process.
   -ml     Trigger when memory commit drops below specified MB value.
   -ma     Write a dump file with all process memory. The default
           dump format only includes thread and handle information.
   -mp     Write a dump file with thread and handle information, and all
           read/write process memory. To minimize dump size, memory areas
           larger than 512MB are searched for, and if found, the largest
           area is excluded. A memory area is the collection of same
           sized memory allocation areas. The removal of this (cache)
           memory reduces Exchange and SQL Server dumps by over 90%.
   -n      Number of dumps to write before exiting.
   -o      Overwrite an existing dump file.
   -p      Trigger on the specified performance counter when the threshold
           is exceeded. Note: to specify a process counter when there are
           multiple instances of the process running, use the process ID
           with the following syntax: "\Process(<name>_<pid>)\counter"
   -pl     Trigger wehen performance counter falls below the specified value.
   -r      Reflect (clone) the process for the dump to minimize the time
           the process is suspended (Windows 7 and higher only).
   -s      Consecutive seconds before dump is written (default is 10).
   -t      Write a dump when the process terminates.
   -u      Treat CPU usage relative to a single core.
   -w      Wait for the specified process to launch if it's not running.
   -x      Launch the specified image with optional arguments.
           If it is a Modern Application or Package, ProcDump will start
           on the next activation (only).

Use the -accepteula command line option to automatically accept the
Sysinternals license agreement.

Use -? -e to see example command lines.

If you omit the dump file name, it defaults to <processname>_<datetime>.dmp.


"   => Defrag Tools: #13  {{{{2
-------------------------------------------------------------------
-- https://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-13-WinDbg
--
-- Note: rename D:\Traveler in files to install folder of "my"
-------------------------------------------------------------------
\my\debuggers\windbg -IA
\my\WinDbg_IA.reg
\my\debuggers\windbg -I
\my\debuggers_x86\windbg -I
\my\WinDbg_AeDebug.reg // Only on Vista and higher

    -------------
    -- windbg -IA
    -------------
    Register windbg for DMP files
    Voegt een open menu toe aan explorer shell menu voor .dmp files

    ----------------
    -- WinDbg_IA.reg
    ----------------
    Wijzigt "open" in "open x64"
    Toevoegen van "open x86"

    ------------
    -- windbg -I
    ------------
    Installeert WinDbg als postmortem debugger

    ---------------------------
    -- WinDbg_AeDebug.reg
    -- Only on Vista and higher
    ---------------------------
    Gives better context when stopping at an exception

"   => Defrag Tools: #14 (SOS)  {{{{2
.load
.loadby
.unload
dv              Display Local Variables
dt              Display Type
!dumpstack
!dso
!do
.prefer_dml 1
.lines
.frame n
lm              List Loaded Modules
lmv             List Loaded Modules Verbose
lm m *clr*

.loadby sos.dll mscorwks -> Loads sos.dll from the folder where mscorwks module resides
.loadby sos.dll clr      -> Loads sos.dll from the folder where clr module resides
dv                       -> view arguments
dt                       -> view argument types

"   => Defrag Tools: #15 - WinDbg - Bugcheck  {{{{2

  ----------
  NotMyFault
  ----------
  Crash your computer in a multitude of ways.
  Just start as administrator and choose an option.
  Note: SYMPATH aanpassen om NotMyFault\symbols\x(86|64) toe te voegen

"   => Defrag Tools: #20 - WinDbg - Basic Commands {{{{2
.cls                    Clear Screen

-------------------------------------------------
-- Commando's om een debugsessie te documenteren.
-------------------------------------------------
version                 The version command displays version information about the debugger and all loaded extension DLLs. This command also displays the current version of the operating system of the target computer
vertarget               The vertarget command displays the current version of the Microsoft Windows operating system of the target computer.
|                       The pipe (|) command displays status for the specified process, or for all processes that you are currently debugging.
||                      The double vertical bar (||) command prints status for the specified system or for all systems that you are currently debugging.
.sympath                The .sympath command changes the default path of the host debugger for symbol search.
.srcpath                The .srcpath and .lsrcpath commands set or display the source file search path.
.exepath                The .exepath command sets or displays the executable file search path.
  --> Een minidump bevat niet de volledige image. .exepath kan dan gebruikt worden om de volledige image in te laden.
.extpath                The .extpath command sets or displays the extension DLL search path.
.chain                  The .chain command lists all loaded debugger extensions in their default search order.

.prefer_dml 1

-------------------------
Actual debugging commands
-------------------------
k                       The k* commands display the stack frame of the given thread, together with related information.
bnf                    b: Displays the first three parameters that are passed to each function in the stack trace.
                        n: Displays frame numbers.
                        f: Displays the distance between adjacent frames. This distance is the number of bytes that separate the frames on the actual stack.
~                       The tilde (~) command displays status for the specified thread or for all threads in the current process.
  *                     display all threads
  .                     display the currently active thread
  #                     display the thread that originally caused the exception
  <n>                   display thread number <n>
!error c0000005         The !error extension decodes and displays information about an error value.
~1k                     Stack trace of thread 1
~1s                     The ~s command sets or displays the current thread number.
~~[<threadid]s          Also sets the current thread. (ordering of thread numbers can be arbitray)
~*k                     Show stack of all threads.
!process 0 17           Equivalent of ~*k in Kernel mode
g                       The g command starts executing the given process or thread. Execution will halt at the end of the program, when BreakAddress is hit, or when another event causes the debugger to stop.
r                       The r command displays or modifies registers, floating-point registers, flags, pseudo-registers, and fixed-name aliases
~*r                     Show all registers of all threads.
!threads                All thred information of current process.
!findstack ntdll!Zw     Find all threads calling into function ntdll!Zw*
!uniqstack              The !uniqstack extension displays all of the stacks for all of the threads in the current process, excluding stacks that appear to have duplicates.
!peb                    The !peb extension displays a formatted view of the information in the process environment block (PEB).
!teb                    The !teb extension displays a formatted view of the information in the thread environment block (TEB).
dps                     The dds, dps, and dqs commands display the contents of memory in the given range. This memory is assumed to be a series of addresses in the symbol table. The corresponding symbols are displayed as well.
  fromAddress
  toAddress
  example   dps esp esp+FF
dpu                     The dda, ddp, ddu, dpa, dpp, dpu, dqa, dqp, and dqu commands display the pointer at the specified location, dereference that pointer, and then display the memory at the resulting location in a variety of formats.
  example   dpu esp esp+FF
lm                      The lm command displays the specified loaded modules. The output includes the status and the path of the module.
.reload /f              The .reload command deletes all symbol information for the specified module and reloads these symbols as needed. In some cases, this command also reloads or unloads the module itself.
                        /f Forces the debugger to immediately load the symbols. This parameter overrides lazy symbol loading.
!gle [-all]             The !gle extension displays the last error value for the current thread.
!tls                    The !tls extension displays a thread local storage (TLS) slot.
!runaway 7              The !runaway extension displays information about the time consumed by each thread

"   => Defrag Tools: #21 - Windbg - Memory {{{{2
!address -summary       The !address extension displays information about the memory that the target process or target computer uses.
!address <addr>
!vprot <addr>           More or less the same as !address
!mapped_file <addr>     The !mapped_file extension displays the name of the file that backs the file mapping that contains a specified address.

"   => Defrag Tools: #22 - Windbg - Memory (kernel) {{{{2
livekd io windbg
----------------
!vm                     The !vm extension displays summary information about virtual memory use statistics on the target system.
!vm 1
!memusage 8             The !memusage extension displays summary statistics about physical memory use. (8 Displays only general summary information about memory use.)
!poolused 2             The !poolused extension displays memory use summaries, based on the tag used for each pool allocation.
!poolused 4
  poolused gebruikt de beschrijvingen in pooltag.txt om extra informatie te tonen. Indien een driver niet is toegevoegd aan pooltag.txt kan deze gezocht worden
  op de 4 characters lange tag door in c:\windows\system32\drivers met strings te zoeken in *.sys bestanden.
  pooltag.txt (d:\Traveler\My\debuggers\triage\pooltag.txt)

!poolfind <tag>
!pool <addr>
!pool <addr> 2
!pte

"   => Defrag Tools: #23 - Windows 8 SDK {{{{2
Installatie van de Windows 8 debugging Toolkit

"   => Defrag Tools: #24 - Windbg - Critical Sections {{{{2
~*k                     Show stack of all threads.
~*kv
~
~~[TID]s
!cs                     The !cs extension displays one or more critical sections or the whole critical section tree.
!cs <pointer>
!locks                  The !locks extension in Ntsdexts.dll displays a list of critical sections associated with the current process.

"   => Defrag Tools: #25 - Windbg - Events {{{{2

  ------------------------------------------------------------------
  http://blogs.msdn.com/b/oldnewthing/archive/2006/06/22/642849.aspx
  ------------------------------------------------------------------
  Manual-reset events are easy to understand: If the event is clear, then a wait on the event is not satisfied.
  If the event is set, then a wait on the event succeeds. Doesn't matter how many people are waiting for the event;
  they all behave the same way, and the state of the event is unaffected by how many people are waiting for it.

  Auto-reset events are more confusing. Probably the easiest way to think about them is as if they were semaphores with a maximum token count of one.
  If the event is clear, then a wait on the event is not satisfied. If the event is set, then one waiter succeeds and the event is reset; the other waiters keep waiting.
  (And from our discussion of PulseEvent, you already know that it is indeterminate which waiter will be released if there is more than one.)

  The gotcha with auto-reset events is the case where you set an event that is already set. Since an event has only two states (set and reset), setting an event that is already set has no effect.
  If you are using an event to control a resource producer/consumer model, then the "setting an event that is already set" case will result in you appearing to "lose" a token.

~*k
~*kv
~
~~[TID]s
dp <addr>
!handle
!handle <handle> <mask>       ex. !handle 14 f
.dumpdebug
!uniqstack
!findstack <text>

"   => Defrag Tools: #26 - Windbg - Semaphores, Mutexes and Timers {{{{2
This installment goes over the commands used to diagnose Semaphores, Mutexes and (Waitable) Timers in a user mode application. For timers, we delve deep in to the kernel to gather more information about them.
We use these commands:

    !handle <handle> <mask>
    !object <name>
    !object <addr>
    !timer
    !timer <addr>
    ub @rip
    dt nt!_KTHREAD <addr>

"   => Defrag Tools: #27 - Windbg - Configure Kernel Debugging {{{{2
This installment goes over the cables and configuration steps required to set up kernel mode debugging.

We use these BCDEdit commands:

    bcdedit
    bcdedit /dbgsettings
    bcdedit /dbgsettings 1394 channel:42
    bcdedit /dbgsettings net hostip:192.168.0.10 port:50000 key:a.b.c.d
    bcdedit /debug on
    bcdedit /debug off

In the debug session, we use these commands:

    .crash
    .dump /f
    lm
    !lmi
    .reload /f
    !drvobj
    !drvobj <module> 2
    bl
    bc *
    be <N>
    bd <N>
    bp <function>
    bm <wildcard>
    x <wildcard>
    g


"   => Defrag Tools: #28 - Windbg - Scheduling {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-28-WinDbg-Scheduling

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue looking at the Debugging Tools for Windows (in particular WinDbg). WinDbg is a debugger that supports user mode debugging of a process, or kernel mode debugging of a computer.

This installment goes over the Windows Scheduler. We look at Running, Ready and Waiting threads, and talks about the effect of Power Management on scheduling.

We use these commands:

    !running
    !running -t
    !ready
    !dpcs
    !thread <addr> 17
    !thread -1 17   (current thread)

Make sure you watch Defrag Tools Episode #1 and Defrag Tools Episode #23 for instructions on how to get the Debugging Tools for Windows and how to set the required environment variables for symbol and source code resolution.

Resources:
Microsoft Data Center Tour

Timeline:
[00:00] - Episode #27's demo issue
[02:47] - Kernel Hangs
[05:18] - !running
[05:48] - Idle Threads & Processor Power Management
[10:10] - !running -t
[13:53] - !ready
[14:15] - Thread State Diagram
[16:45] - Saturated example
[20:48] - Thread Priority Diagram
[22:22] - Balance Set Manager
[25:30] - Waiting Threads
[26:52] - Summary

"   => Defrag Tools: #29 - Windbg - ETW Logging {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-29-WinDbg-ETW-Logging

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue looking at the Debugging Tools for Windows (in particular WinDbg). WinDbg is a debugger that supports user mode debugging of a process, or kernel mode debugging of a computer.

This installment goes over the Event Tracing for Windows (ETW) buffers in a kernel mode dump or live session. The ETW buffers can be extracted from the dump and viewed using the Windows Performance Toolkit (WPT). The buffers give you insight in to what has beem happening recently on the computer.

We use these commands:

    !wmitrace.strdump
    !wmitrace.logsave 0xNN c:\example.etl
    !wmitrace.eventlogdump 0xNN
    !wmitrace.help

Make sure you watch Defrag Tools Episode #1 and Defrag Tools Episode #23 for instructions on how to get the Debugging Tools for Windows and how to set the required environment variables for symbol and source code resolution. This episode shows how install the Windows Performance Toolkit.

Timeline:
[00:00] - Event Tracing for Windows (ETW)
[02:18] - Windows Performance Toolkit (WPT)
[03:48] - !wmitrace.strdump
[04:53] - !wmitrace.logsave 0xNN c:\example.etl
[05:50] - Windows Performance Analyzer (WPA) & xPerfView
[07:57] - _NT_SYMCACHE_PATH
[10:24] - !wmitrace.eventlogdump 0xNN
[12:16] - Used for logging and performance by many teams
[15:35] - Private PDBs are needed to decode some entries
[20:00] - Windows Performance Recorder (wprui.exe)
[20:35] - Disable Paging Executive
[23:40] - WPR adds the NT Kernel Logger
[24:19] - 10min run-through of the data collected with the General, CPU and Disk providers

"   => Defrag Tools: #30 - MCTS Windows Int {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/DefragTools30

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen review MCP exam 70-660 - MCTS Windows Internals.

Resources:
MCTS Windows Internals
Windows Internals Books
Kernrate
Poolmon
UMDH

Timeline:
[01:42] - Summary of the exam
[03:00] - Windows Internals books
[05:50] - Identifying Architectural Components
[14:17] - Designing Solutions
[21:34] - Monitoring Windows
[29:25] - Analyzing User Mode
[41:39] - Analyzing Kernel Mode
[45:17] - Debugging Windows
[48:32] - Good Luck!

"   => Defrag Tools: #31 - Zoomit {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-31-ZoomIt

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen walk you through Sysinternals ZoomIt. ZoomIt is a screen zoom and annotation tool for technical presentations that include application demonstrations. ZoomIt runs unobtrusively in the tray and activates with customizable hotkeys to zoom in on an area of the screen, move around while zoomed, and draw on the zoomed image.

Resources:
Sysinternals ZoomIt
Sysinternals Administrator's Reference - [Amazon]

Timeline:
[00:00] - Overview
[01:42] - Windows Magnifier (Win-+)
[03:35] - Ctrl-1 - Static Zoom
[05:30] - Ctrl-2 - Draw
[06:38] - Ctrl-4 - Live Zoom
[08:12] - File Save *
[10:05] - Ctrl-3 - Break Timer

* Zoomed to 480x300 on a 1920x1200 screen, the file sizes are:

    Zoomed - 1920x1200
    Actual - 480x300

"   => Defrag Tools: #32 - Desktops {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-32-Desktops

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen walk you through Sysinternals Desktops. Desktops allows you to organize your applications on up to four virtual desktops. We go under the covers and show how Desktops fits in to the Session, Window Station and Desktop object/security model.

** I didn't do a great job explaining Sessions/Window Stations/Desktops -- If you want to know about those concepts in detail, I suggest you watch Sysinternals Primer: Gems instead.

Resources:
Sysinternals Desktops
Sysinternals WinObj
Sysinternals LogonSessions
Aaron Margosis' TSSessions
Sysinternals Administrator's Reference - [Amazon]
Sysinternals Primer: Gems [TechEd EMEA 2012 @13:45]
Malware Hunting with the Sysinternals Tools [TechEd USA 2012 @ 44:30]

Timeline:
[01:05] - Sysinternals Desktops
[04:50] - Sessions, Window Stations and Desktops
[05:13] - Sysinternals WinObj
[05:43] - Sessions
[06:40] - Window Stations
[09:00] - Enumeration (Standard User)
[10:11] - Desktops
[11:38] - Local Security Authority (LSA) - Sessions via Logons *
[12:16] - Enumeration (Elevated User)
[15:20] - psexec -sid cmd.exe
[16:38] - Enumeration (NT Authority\SYSTEM)
[17:15] - Sessions via Logons (NT Authority\SYSTEM)
[18:26] - Media Center Extender example

* You can enumerate sessions directly via the Remote Desktop Services API.

Exercises:

Use Sysinternals LogonSessions to view the logon sessions.
Use Aaron Margosis' TSSessions to view the Sessions/Window Stations/Desktops (and much more).

Session: 0
  WinStation: WinSta0
    Desktop: Default
    Desktop: Disconnect
    Desktop: Winlogon
  WinStation: Service-0x0-3e4$
  WinStation: Service-0x0-3e5$
  WinStation: Service-0x0-3e7$
  WinStation: msswindowstation
     Desktop: mssrestricteddesk
Session: 1
  WinStation: WinSta0
    Desktop: Default
    Desktop: Disconnect
    Desktop: Winlogon

"   => Defrag Tools: #33 - CLR GC - Part 1 {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-33-CLR-GC-Part-1

In this episode of Defrag Tools, Andrew Richards, Maoni Stephens and Larry Larsen walk you through the CLR Garbage Collector. Maoni is the Principal developer for the GC on the CLR team.

Resources:
Maoni's WebLog
Channel9 - CLR 4 Garbage Collector - Inside Background GC
Channel9 - CLR 4.5: Maoni Stephens - Server Background GC
MSDN Magazine - Investigating Memory Issues

Timeline:
[00:00] - What is a Garbage Collector (GC)?
[02:40] - How has the GC changed?
[06:02] - Memory issues
[08:57] - Stress Log (!sos.dumplog)
[10:08] - Troubleshooting and Performance
[12:20] - Demo App
[14:20] - !sos.eeheap -gc
[18:08] - !sos.dumpheap -stat
[20:38] - !sos.dumpheap -mt <mt> (Method Table)
[21:58] - !sos.dumpobj / !sos.do (Dump Object)
[24:15] - Performance Monitoring (SOS, PerfView, Performance Monitor)
[28:06] - Measure immediately after an action, not at a cadence
[29:45] - x clr!WKS::GCHeap::GcCondemnedGeneration (Current GC being collected)
[31:15] - bp clr!WKS::GCHeap::RestartEE (Break after a GC)
[35:30] - More next week...

"   => Defrag Tools: #40 - WPT - WPR & WPA {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-40-WPT-WPR-WPA

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT).

Resources:
Defrag Tools: #23 - Windows 8 SDK
Defrag Tools: #29 - WinDbg - ETW Logging
Windows Performance Analysis Developer Center
Windows Performance Toolkit
Channel 9 Videos
NTDebugging Blog Article
PFE Blog Series

Timeline:
[00:40] - Windows Performance Recorder (UI)
[06:00] - Windows Performance Analyzer
[06:40] - Providers vs. Visualization
[08:00] - (CPU Usage) Sampled vs. Precise
[12:30] - Analysis Pane
[14:11] - * I was thinking of MDI (Multiple Document Interface]
[14:35] - Blue Bar
[15:27] - Gold/Yellow Bar - How to Aggregate
[19:18] - Symbols & SymCache
[28:40] - Column Customization
[31:50] - More next week... and many more weeks to come!

"   => Defrag Tools: #41 - WPT - Command Line {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-41-WPT-Command-Line

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT). Example xPerf scripts.

Resources:
Defrag Tools: #23 - Windows 8 SDK
Defrag Tools: #29 - WinDbg - ETW Logging
Windows Performance Analysis Developer Center
Windows Performance Toolkit
Channel 9 Videos
NTDebugging Blog Article
PFE Blog Series

Timeline:
[00:00] - UI vs. Command Line
[02:15] - wpr.exe -profiles
[02:48] - wpr.exe -profiledetails <profile>
[05:30] - wpr.exe -start <profile>
[06:06] - wpr.exe -stop result.etl
[09:25] - xperf.exe -help
[09:30] - xperf.exe -providers kg
[12:18] - xperf.exe -providers kf
[16:47] - xperf.exe -on <FLAG+FLAG+...>
[18:17] - xperf.exe -stop -d result.etl
[21:42] - xperf.exe ... -BufferSize <Size in KB>
[25:55] - xperf.exe ... -MinBuffers <Number> -MaxBuffers <Number>
[27:08] - xperf.exe ... -MaxFile <Size in KB>
[27:44] - xperf.exe ... -FileMode Circular
[30:42] - xperf.exe -merge <in-file1> <in-file2> <out-file>
[32:28] - Andrew's Scripts on SkyDrive [link]
[33:15] - xperf.exe -help stackwalk
[35:10] - xperf.exe ... -stackwalk <Stack+Stack+...>

Examples:
wpr.exe -start GeneralProfile
pause
wpr.exe -stop result.etl

xperf.exe -on Base -stackwalk Profile -BufferSize 1024 -MinBuffers 256 -MaxBuffes 256 -MaxFile 256 -FileMode Circular
pause
xperf.exe -stop -d result.etl

"   => Defrag Tools: #42 - WPT - CPU Analysis {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-42-WPT-CPU-Analysis

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT). Example xPerf scripts.

Resources:
Defrag Tools: #23 - Windows 8 SDK
Defrag Tools: #29 - WinDbg - ETW Logging
Windows Performance Analysis Developer Center
Windows Performance Toolkit
Channel 9 Videos
NTDebugging Blog Article
PFE Blog Series

Timeline:
[01:20] - xperf.exe -on PROFILE -StackWalk Profile
[04:40] - xperf.exe -on PROC_THREAD+LOADER+PROFILE -StackWalk Profile
[06:14] - Lots of Views
[08:36] - View CPU by Module
[10:09] - View CPU by Stack
[14:52] - xperf.exe -on PROC_THREAD+LOADER+PROFILE+INTERRUPT+DPC -StackWalk Profile
[20:18] - DPC Timeline
[23:13] - DPC/ISR Per-CPU Analysis
[25:42] - Example of a DPC/ISR Spike
[33:35] - Summary

Example: "xperf - Collect CPU.cmd"

@echo off
echo Press a key when ready to start...
pause
echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+PROFILE+INTERRUPT+DPC -stackwalk Profile -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -d cpu.etl

"   => Defrag Tools: #43 - WPT - CPU Wait Analysis {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-43-WPT-Wait-Analysis

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT). Example xPerf scripts.

Resources:
Defrag Tools: #23 - Windows 8 SDK
Defrag Tools: #29 - WinDbg - ETW Logging
Windows Performance Analysis Developer Center
Windows Performance Toolkit
Channel 9 Videos
NTDebugging Blog Article
PFE Blog Series

Timeline:
[01:05] - xperf -on PROC_THREAD+LOADER+PROFILE+INTERRUPT+DPC+DISPATCHER+CSWITCH -stackwalk Profile+CSwitch+ReadyThread
[01:50] - Synchronization Episodes: #24, #25 & #26
[02:10] - CSwitch (a.k.a. NewThread) and ReadyThread stacks
[03:36] - Aaron's Margosis' VirtMemTest "Hang the UI" example
[05:15] - CPU (Precise)
  NewProcess
  NewThreadId
  NewStack
  ReadyingProcess
  ReadyingThreadId
  ReadyingStack
  Waits(us)
[17:30] - Summary

Example: "xperf - Collect CPUWait.cmd"

@echo off
echo Press a key when ready to start...
pause
echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+PROFILE+INTERRUPT+DPC+DISPATCHER+CSWITCH -stackwalk Profile+CSwitch+ReadyThread -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -d cpuwait.etl

"   => Defrag Tools: #44 - WPT - DiskIO Analysis {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-44-WPT-DiskIO-Analysis

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT). Example xPerf scripts.

Resources:
Defrag Tools: #23 - Windows 8 SDK
Defrag Tools: #29 - WinDbg - ETW Logging
Windows Performance Analysis Developer Center
Windows Performance Toolkit
Channel 9 Videos
NTDebugging Blog Article
PFE Blog Series

Timeline:
[00:30] - xperf -on PROC_THREAD+LOADER+DISK_IO+DISK_IO_INIT -stackwalk DiskReadInit+DiskWriteInit+DiskFlushInit
[02:00] - WPA
[03:22] - System Configuration
[04:30] - Disk Queue Length - need to use xPerfView
[06:32] - Disk Controllers, Disk Drives and RAID
[11:08] - * The 2nd thing is AHCI which does I/O reordering (forgot to mention it)
[15:45] - xPerfView - Disk I/O "Detail Graph"
[18:30] - WPA - IO Time & Disk Service Time
[22:45] - xPerfView - Disk Queue Length
[25:00] - Summary

Example: "xperf - Collect DiskIO.cmd"

@echo off
echo Press a key when ready to start...
pause

echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+DISK_IO+DISK_IO_INIT -stackwalk DiskReadInit+DiskWriteInit+DiskFlushInit -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -d diskio.etl

"   => Defrag Tools: #45 - WPT - File & Registry Analysis {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-45-WPT-File--Registry-Analysis

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT). Example xPerf scripts.

Resources:
Defrag Tools: #23 - Windows 8 SDK
Defrag Tools: #29 - WinDbg - ETW Logging
Windows Performance Analysis Developer Center
Windows Performance Toolkit
Channel 9 Videos
NTDebugging Blog Article
PFE Blog Series

Timeline:
File
[00:00] - Process Monitor vs. WPT
[01:48] - xperf -on PROC_THREAD+LOADER+FILENAME+FILE_IO+FILE_IO_INIT -stackwalk ...
[03:43] - Process Monitor design (I asked Mark; filtering is done in User Mode)
[05:25] - WPA - File Analysis
[09:42] - Comparison to Process Monitor "Enable Advanced Output"
Registry
[16:47] - xperf -on PROC_THREAD+LOADER+REGISTRY -stackwalk ...
[18:25] - WPR Profiles (FileIO & Registry)
[20:50] - WPA - Registry Analysis
Registry Hive
[25:55] - xperf -on PROC_THREAD+LOADER+REG_HIVE -stackwalk ...
[28:22] - Logoff/Logon to show Registry Hive unload/load
[29:10] - WPA - Registry Hive Analysis
Summary
[33:16] - Summary



Example: "xperf - Collect FileIO.cmd"

@echo off
echo Press a key when ready to start...
pause

echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+FILENAME+FILE_IO+FILE_IO_INIT -stackwalk FileCreate+FileCleanup+FileClose+FileRead+FileWrite+FileSetInformation+FileDelete+FileRename+FileDirEnum+FileFlush+FileQueryInformation -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -d fileio.etl



Example: "xperf - Collect Registry.cmd"

@echo off
echo Press a key when ready to start...
pause

echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+REGISTRY -stackwalk RegQueryKey+RegEnumerateKey+RegEnumerateValueKey+RegDeleteKey+RegCreateKey+RegOpenKey+RegSetValue+RegDeleteValue+RegQueryValue+RegQueryMultipleValue+RegSetInformation+RegFlush+RegKcbCreate+RegKcbDelete+RegVirtualize+RegCloseKey -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -d registry.etl



Example: "xperf - Collect RegHive.cmd"

@echo off
echo Press a key when ready to start...
pause

echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+REG_HIVE -stackwalk RegHiveInit+RegHiveDestroy+RegHiveLink+RegHiveDirty -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -d reghive.etl

"   => Defrag Tools: #46 - WPT - Driver Analysis {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-46-WPT-Driver-Analysis

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT). Example xPerf scripts.

Resources:
Defrag Tools: #23 - Windows 8 SDK
Defrag Tools: #29 - WinDbg - ETW Logging
Windows Performance Analysis Developer Center
Windows Performance Toolkit
Channel 9 Videos
NTDebugging Blog Article
PFE Blog Series

Timeline:
[00:32] - xperf -on PROC_THREAD+LOADER+PROFILE+DRIVERS -stackwalk ...
[01:27] - xPerfView - Driver Delays
[05:09] - WPA
[05:50] - Device Stack & IRPs
[09:14] - Advanced Settings (Filter)
[12:14] - Long Duration example
[13:30] - Zoom and then look at other graphs - e.g. CPU Usage (Sampled)
[15:22] - Summary

Example: "xperf - Collect Drivers.cmd"

@echo off
echo Press a key when ready to start...
pause

echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+PROFILE+DRIVERS -stackwalk Profile -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -d drivers.etl

"   => Defrag Tools: #47 - WPT - Minifilter Analysis {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-47-WPT-MiniFilter-Analysis

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT). Example xPerf scripts.

Resources:
Defrag Tools: #23 - Windows 8 SDK
Defrag Tools: #29 - WinDbg - ETW Logging
Windows Performance Analysis Developer Center
Windows Performance Toolkit
Channel 9 Videos
NTDebugging Blog Article
PFE Blog Series

Timeline:
{T00:00] - Filters & MiniFilters
[04:48] - xperf -on PROC_THREAD+LOADER+PROFILE+FLT_IO_INIT+FLT_IO+FLT_FASTIO+FLT_IO_FAILURE+FILENAME -stackwalk ...
[07:30] - WPA
[09:48] - IRP - Major Function
[11:30] - Filter to Major Functiom, then sort by Mini-Filter Driver
[14:20] - Zoom and then look at other graphs - e.g. CPU Usage (Sampled)
[15:25] - Summary

Example: "xperf - Collect MiniFilter.cmd"

@echo off
echo Press a key when ready to start...
pause

echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+PROFILE+FLT_IO_INIT+FLT_IO+FLT_FASTIO+FLT_IO_FAILURE+FILENAME -stackwalk Profile+MiniFilterPreOpInit+MiniFilterPostOpInit -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -d minifilter.etl

"   => Defrag Tools: #48 - WPT - Memory Analysis - Pool {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-48-WPT-Memory-Analysis-Pool

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT). This is part 1 of 3 episodes on memory usage/leaks. Example xPerf scripts.

Resources:
Defrag Tools: #6 - RAMMap
Defrag Tools: #22 - WinDbg - Memory Kernel Mode
Pushing the Limits of Windows: Paged and Nonpaged Pool
Sysinternals RAMMap
Sysinternals LiveKd
Windows Internals Book - NotMyFault

Timeline:
[00:00] - Paged and Nonpaged Pool
[03:10] - RAMMap
[06:23] - LiveKd - !poolused 2
[08:22] - xperf -on PROC_THREAD+LOADER+POOL -stackwalk ...
[09:00] - NotMyFault
[09:55] - WPA
[10:50] - Type - Allocated Inside (AI) & Outside (AO), Freed Inside (FI) & Outside (FO)
[14:33] - Summary

Example: "xperf - Collect Pool.cmd"

@echo off
echo Press a key when ready to start...
pause

echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+POOL -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -d pool.etl

"   => Defrag Tools: #49 - WPT - Memory Analysis - VirtualAlloc {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-49-WPT-Memory-Analysis-VirtualAlloc

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT). This is part 2 of 3 episodes on memory usage/leaks. Example xPerf scripts.

Resources:
Defrag Tools: #7 - VMMap
Sysinternals VMMap
Aaron Margosis VirtMemTest

Timeline:
[00:00] - Happy 1st Birthday Defrag Tools!
[00:52] - VMMap
[01:22] - VirtMemTest
[03:43] - xperf -on PROC_THREAD+LOADER+VIRT_ALLOC -stackwalk ...
[04:46] - WPA
[06:30] - Commit Type - Allocated Inside (AI) & Outside (AO), Freed Inside (FI) & Outside (FO)
[08:02] - VirtualAlloc vs Heap

Example: "xperf - Collect VirtualAlloc.cmd"

@echo off
echo Press a key when ready to start...
pause

echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+VIRT_ALLOC -stackwalk VirtualAlloc+VirtualFree -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -d virtualalloc.etl

"   => Defrag Tools: #50 - WPT - Memory Analysis - Heap {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-50-WPT-Memory-Analysis-Heap

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen continue walking you through the Windows Performance Toolkit (WPT). This is part 3 of 3 episodes on memory usage/leaks. Example xPerf scripts.

Resources:
Aaron Margosis VirtMemTest

Timeline:
[00:00] - 50th Episode of Defrag Tools!
[01:20] - Attach: xperf -start HeapSession -heap -pids %1 -stackwalk ...
[03:28] - VirtMemTest
[04:54] - WPA
[06:22] - Type - Allocated Inside (AI) & Outside (AO), Freed Inside (FI) & Outside (FO)
[07:20] - Launch: Image File Execution Options
[07:51] - Launch: xperf -start HeapSession -heap -pids 0 -stackwalk ...
[08:40] - Registry Editor - IFEO
[10:26] - WPA
[11:06] - Type - Allocated Inside (AI) & Outside (AO), Freed Inside (FI) & Outside (FO)
[11:25] - Summary - AIFO

Example: "xperf - Collect Heap_Attach.cmd"

@echo off
echo Press a key when ready to start...
pause

echo .
echo ...Capturing...
echo .

xperf -on PROC_THREAD+LOADER+VIRT_ALLOC -stackwalk VirtualAlloc+VirtualFree -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular
xperf -start HeapSession -heap -pids %1 -stackwalk HeapAlloc+HeapRealloc -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop -stop HeapSession -d heap.etl

Example: "xperf - Collect Heap_Launch.cmd"

@echo off
echo Press a key when ready to start...
pause

echo .
echo ...Capturing...
echo .

rem Add the process to IFEO
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%1.exe" /v TracingFlags /t REG_DWORD /d 1 /f

xperf -on PROC_THREAD+LOADER+VIRT_ALLOC -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -stackwalk VirtualAlloc
xperf -start HeapSession -heap -pids 0 -stackwalk HeapAlloc+HeapRealloc -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

echo Press a key when you want to stop...
pause
echo .
echo ...Stopping...
echo .

xperf -stop HeapSession -stop -d heap.etl

rem Remove the process from IFEO
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%1.exe" /v TracingFlags /f

"   => Defrag Tools: #51 - Support Diagnostics {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-51-Support-Diagnostics

In this two part series of Defrag Tools, Andrew Richards and Larry Larsen talk to Jeff Dailey, Director of diagnostics in Microsoft Support. In this episode, we cover the principals of data collection and analysis.

"   => Defrag Tools: #52 - Microsoft Fix it Center Pro {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-52-Microsoft-Fix-it-Center-Pro

In this two part series of Defrag Tools, Andrew Richards and Larry Larsen talk to Jeff Dailey, Director of diagnostics in Microsoft Support. In this episode, we talk about Microsoft Fix it Center Pro.
"   => Defrag Tools: #53 - Crashes, Hangs and Slow Performance {{{{2
channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-53-Crashes-Hangs-and-Slow-Performance

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen talk about Crashes, Hangs and Slow Performance. We talk about how to approach these issues and list the tools that can help you analyze them.

Resources:
Sysinternals VMMap
Sysinternals ProcDump
Debugging Tools for Windows
Windows Performance Toolkit

Timeline:
[00:00] - General Troubleshooting
[00:34] - Crashes
[04:10] - Windows Error Reporting
[04:40] - AeDebug
[09:15] - Event Viewer - Application Log - "Source:Application Error, Event ID:1000"
[10:10] - BSOD
[10:51] - Event Viewer - System Log - "Source:BugCheck, Event ID:1001"
[11:54] - System | Advanced | Startup and Recovery - Restart
[13:55] - OCA
[15:15] - Hangs
[17:09] - Forcing a Hard Reboot (ACPI)
[18:50] - Store app hangs - PLM restarts app on hang
[19:48] - Desktop app hangs - "Not Responding" - DWM desktop composition
[26:44] - Slow Performance
[27:10] - Windows Performance Toolkit
[29:09] - Email us your issues at defragtools@microsoft.com
"   => Defrag Tools: #54 - IE Favorites Crash {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-54-IE-Favorites-Crash

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen show you the analysis of a crash. The crash happens when Favorites is clicked in Internet Explorer. We show Andrew's debugging and troubleshooting steps to solve the issue.

Resources:
Sysinternals Process Monitor
Sysinternals ProcDump
Debugging Tools for Windows
Windows Performance Toolkit
SkyDrive - procdumpext.dll

Timeline:
[00:00] - Windows 8.1 RTM!
[01:18] - Internet Explorer Favorites Crash
[01:50] - AeDebug - (procdump.exe -ma -i c:\dumps)
[02:00] - Open the dump in the Debugger
[02:15] - Review crash at the exception context - .ecxr
[03:32] - View the exception record - .exr -1
[03:58] - View the stack - k
[04:17] - Explorer - C:\Users\<user>\Favorites
[05:00] - Deleted suspicious file but still crashes
[05:07] - Back to the dump file to get more evidence
[06:05] - !procdumpext.dpx
[07:50] - Trace Registry activity with Process Monitor
[10:45] - Use Jump To to navigate to the key in RegEdit
[11:28] - Rename the key as the data seems to come from it (as seen in the dump)
[12:22] - Success!
[13:25] - Email us your issues at defragtools@microsoft.com
"   => Defrag Tools: #55 - Bugcheck 0xAB Crash {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-55-Bugcheck-0xAB-Crash

In this episode of Defrag Tools, Chad Beeder, Andrew Richards and Larry Larsen show you the analysis of a Bugcheck 0xAB (by C9'er David Grainger). We show Chad's debugging and troubleshooting steps to solve the issue.

Resources:
Debugging Tools for Windows

Timeline:
[00:00] - Bugcheck 0xAB by C9'er David Grainger
[01:03] - C:\Windows\MiniDumps
[01:48] - Changed to Complete Dump (Win-X | System)
[02:47] - Open the dump in the Debugger
[03:00] - !analyze -v
[03:29] - Windows Internals book - Session Space
[04:36] - Back to the dump... pool tag Gh1?
[06:53] - Windows GDI - we were all wrong, it's "graphics device interface"
[07:54] - Send to Microsoft
[08:48] - August 2013 Update Rollup - KB2862768
[09:00] - Display pointer trails - KB2865941
[11:27] - Email us your issues at defragtools@microsoft.com
"   => Defrag Tools: #56 - Explorer Hang {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-56-Explorer-Hang

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen show you the analysis of a hang. The hang happens in Explorer when Windows-E is pressed - the folder window never appears. We show Andrew's debugging steps to solve the issue.

Resources:
Debugging Tools for Windows
SkyDrive - procdumpext.dll
SkyDrive - sieextpub.dll

Timeline:
[00:00] - Explorer Hang
[01:35] - Open the dump in the Debugger
[01:59] - List Threads - "~"
[02:20] - List thread stacks - ~*k
[02:46] - List thread stacks - !procdumpext.deep 20
[03:23] - Review of Thread #2
[04:03] - Review of Thread #5
[05:21] - Look for Unicode strings - dpu <addr> <addr>
[06:36] - Internet Explorer Security Zones
[07:08] - Loader Lock (Ldr* routines)
[08:30] - Review of Thread #6
[09:21] - Look for Unicode strings - dpu <addr> <addr>
[10:30] - Display Unicode strings - du <addr>
[12:56] - Force Symbol Load - .reload /f
[13:28] - Use grep to filter to 3rd Party Modules - !procdumpext.grep export lm
[13:56] - RBVirtualFolder64 is from Roxio - lmvm RBVirtualFolder64
[14:21] - Look for Unicode strings - !procdumpext.dpx -du
[14:50] - Large Dispositions (caused by no symbols)
[15:46] - List exported functions - x <module>!*
[16:25] - Unassemble - u RBVirtualFolder64!DllRegisterServer
[18:12] - Loader Lock (Ldr* routines)
[18:45] - Critical Section Lock Ownership - !locks
[24:04] - It's a Deadlock!
[24:27] - Easy Analysis - !sieextpub.critlist
[26:02] - Only do kernel32 synchronization object creation while holding the Loader Lock!
[27:50] - Summary
[29:35] - Email us your issues at defragtools@microsoft.com

"   => Defrag Tools: #57 - New Job, New Systems, 2 Questions and 2 Crashes {{{{2
http://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-57-New-Job-New-Systems-2-Questions-and-2-Crashes

In this episode of Defrag Tools, Andrew Richards, Chad Beeder and Larry Larsen talk about Andrew's new job, configuring new systems with SSDs and HDDs, answer two questions from a viewer (Barry), and debug two crashes.

[So why is the audio weird in this episode? Well, Andrew accidently hit mute on his mic just before recording. Kaitlin came to the rescue and used the audio from Chad's mic, fixing the levels for hours - Thx Kaitlin]

Resources:
Debugging Tools for Windows
SkyDrive - procdumpext.dll

Timeline:
[00:00] - Andrew's new job - "Send to Microsoft"
[01:53] - How we'd set up machines with SSDs and HDDs
[04:30] - Making a folder on C: (SSD) that redirects to another drive (HDD)
[05:00] - Mount Point via Disk Management
[06:08] - Symbolic Link - mklink /d Link Target
[08:25] - Question #1 - "Application Hang" (Event ID 1002)
[08:25] - Windows Error Reporting LocalDumps
[12:13] - Question #2 - "User reported a hang"
[15:48] - Crash #1 - NULL Pointer
[17:30] - Unassemble (backwards and forwards) - ub @rip and u @rip
[17:30] - List module - lmvm <module>
[24:08] - Crash #2 - Unloaded Module
[24:39] - List (Unloaded) modules - lm
[25:30] - List Stacks with Unloaded modules - !procdumpext.seek Unloaded
[27:29] - Email us your issues at defragtools@microsoft.com

Window Error Reporting LocalDumps - create Full Dump:

Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps]
"DumpFolder"="\"C:\\dumps"
"DumpType"=dword:00000002
"DumpCount"=dword:0000000a
