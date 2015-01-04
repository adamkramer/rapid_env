rapid_env
=========

Rapid deployment of Windows environment (files, registry keys, mutex etc) to facilitate malware analysis

rapid_env - Created by Adam Kramer [2015]
----------------------------------------------------------- 
This program rapidly sets up a malware analysis environment based on configuration file specified by the user.
Configuration file can contain the following lines:

To create a file:
file:path=content   (content is optional) 

To create a registry key:
registry:key=value|data   (value|data is optional) 

To launch a process with specific name:
process:process name

To create a mutex:
mutex:mutex name

Lines beginning with # are ignored as comments

Example config file:
# A file, which has content in
file:C:\Users\User\Documents\test.txt=This is the content of the file
# A file, with no content
file:C:\Users\User\Documents\test.txt
# Notice the registry entry needs to start with HKEY_CURRENT_USER, this can be any other hive but full name is required
registry:HKEY_CURRENT_USER\SOFTWARE\Test=password|john
# Example mutex
mutex:thisisabadmutex
# This won't run Windows calc.exe, but rather a skeleton process with the name requested
process:calc.exe
