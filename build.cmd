@echo off
rem Builds ArchiveSpaceSaver.exe using the C# compiler that ships with Windows (nothing to install).
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
cd /d "%~dp0"
"%CSC%" /nologo /target:winexe /platform:x64 /optimize+ /warn:4 /win32manifest:app.manifest /out:ArchiveSpaceSaver.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll ArchiveSpaceSaver.cs
