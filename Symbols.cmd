@echo off

:INITIALIZATION
  @rem ***
  @rem *  We gaan er van uit dat alle instellingen kunnen
  @rem *  gebeuren tov van het path waaruit de cmd is opgestart (normaal c:\my)
  @rem *
  set input=
  set MyRoot=%~dp0
  echo Is "%MyRoot%" gebruikt als installatiefolder. (Y/N)
  echo "Volgende folderstructuur zal worden aangemaakt:"
  echo "%MyRoot%Src"
  echo "%MyRoot%Sym"
  echo "%MyRoot%SymCache"
  set /p input=type input: %=%
  if %input%==n goto HELP
  if %input%==N goto HELP
  goto INSTALL

:HELP
  @rem ***
  @rem *  We gaan er van uit dat alle instellingen kunnen
  @rem *  gebeuren tov van het path waaruit de cmd is opgestart
  @rem *
  @rem
  goto EXIT_SCRIPT

:INSTALL
  md %MyRoot%Src
  md %MyRoot%Sym
  echo 000Admin is needed in case of using convertstore to change from 2 tier to 3 tier indexing
  md %MyRoot%Sym\000Admin
  echo "index2.txt enables 3 Tier indexing." > %MyRoot%Sym\index2.txt
  md %MyRoot%SymCache
  compact /c /s /i /q %MyRoot%Sym\*.*
  compact /c /s /i /q %MyRoot%SymCache\*.*

  setx /m _NT_SOURCE_PATH SRV*%MyRoot%Src*http://msdl.microsoft.com/download/symbols
  setx /m _NT_SYMBOL_PATH SRV*%MyRoot%Sym*http://msdl.microsoft.com/download/symbols
  setx /m _NT_SYMCACHE_PATH %MyRoot%SymCache
  setx /m _NT_DEBUGGER_EXTENSION_PATH "%MyRoot%debuggers\winext"
  setx /m _NT_PDE_ARCHFLIP 1

  rem rem Not foolproof yet.
  rem rem 1. setx is limitted to 1024 characters?
  rem rem 2. %MyRoot% is niet correct voor D:\Traveler. (\My moet er nog bij in dat geval).
  setx path "%path%;%MyRoot%SysInternals"
  rem rem setx path "%path%;%MyRoot%Beyond Compare 3"
  rem rem setx path "%path%;%MyRoot%Git"
  rem rem setx path "%path%;%MyRoot%PowerGREP4"
  rem rem setx path "%path%;%MyRoot%Regexbuddy"
  rem rem setx path "%path%;%MyRoot%Vim"
  rem rem setx path "%path%;%MyRoot%application_verifier"
  rem rem setx path "%path%;%MyRoot%application_verifier_x86"
  rem rem setx path "%path%;%MyRoot%debuggers"
  rem rem setx path "%path%;%MyRoot%debuggers_x86"
  rem rem setx path "%path%;%MyRoot%git\bin"
  rem rem setx path "%path%;%MyRoot%pict"
  rem rem setx path "%path%;%MyRoot%sysinternals"
  rem rem setx path "%path%;%MyRoot%vim\vim73"
  rem rem setx path "%path%;%MyRoot%windows_performance_toolkit"

:EXIT_SCRIPT
pause
