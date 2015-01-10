/*  This program is free software: you can redistribute it and/or modify 
    it under the terms of the GNU General Public License as published by 
    the Free Software Foundation, either version 3 of the License, or 
    (at your option) any later version. 
 
    This program is distributed in the hope that it will be useful, 
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
    GNU General Public License for more details. 
 
    You should have received a copy of the GNU General Public License 
    along with this program.  If not, see <http://www.gnu.org/licenses/>.  
	 
	Created by Adam Kramer [2014] - Email: adamkramer at hotmail dot com */ 

#include "stdafx.h"
#include "stdio.h"
#include "windows.h"

int main(int argc, char *argv[])
{
	printf("      *** rapid_env - Created by Adam Kramer [2015] ***\n");
	printf("-----------------------------------------------------------\n");

	if (argc < 2) {
	
		printf("This program rapidly sets up a malware analysis environment\n");
		printf("based on configuration file specified by the user\n\n");
		printf("Configuration file can contain the following lines:\n");
		printf("*** To create a file ***\n");
		printf("file:<path>=<content>   (<content> is optional)\n");
		printf("*** To create a registry key ***\n");
		printf("registry:<key>=<value>|<data>   (<value>|<data> is optional)\n");
		printf("*** To launch a process with specific name ***\n");	
		printf("process:<process name>\n");
		printf("*** To create a mutex ***\n");
		printf("mutex:<mutex name>\n");
		printf("## Lines beginning with # are ignored as comments ##\n\n");
		printf("Usage: rapid_env.exe <config file> [undo]\n");
	
		return 0;
	}

	/* This launches the application in 'Skeleton mode' - which is used when launching a named process */
	if (!_strcmpi(argv[1], "!skeleton!"))
	{
		wprintf(L"Launching in skeleton mode - no further action will be taken\n");
		for (;;) 
			Sleep(10000);
	}

	/* Variables:
		bKeepActive - This is used to identify whether the program needs to remain open
					  Will be made true if subprocesses or mutex are created
	    
		bUndo		- Identifies whether the 'undo' parameter has been passed, to
					  return system to original state									*/
	bool bKeepActive = false;
	bool bUndo = false;

	/* If 'undo' argument is passed, put into undo mode */
	if (argc > 2 && !_strcmpi(argv[2], "undo"))
		bUndo = true;
	
	/* Open handle to configuration file */
	FILE *fp;
	fopen_s(&fp, argv[1], "r");

	/* Create variables to hold the data on each line of the config file */
	wchar_t cCommand[1024], cValue[1024], cOptional[1024], cInput[1024];

	/* Error handling for config file opening */
	if (!fp) {
		printf("Error: could not open %s\n", argv[1]);
		return 1;
	}

	/* Configuration file reading loop */
	while (fgetws(cInput, sizeof(cInput), fp)) {
		
		/* If the first character is a #, this is a comment line, so skip (or  blank lines) */
		if (*cInput == '#' || *cInput == '\r' || *cInput == '\n') continue;

		/* Format data read into the variables, command type, value and optional extra parameter */
		if (swscanf_s(cInput, L"%[^:]:%[^=]=%[^\r\n]", cCommand, _countof(cCommand), cValue, _countof(cValue), cOptional, _countof(cOptional)) < 2){
			printf("Info: Ignoring invalid configuration entry\n");
			continue;
		}

		/* Strip next line character from end of any of the variables (causes issues later) */
		unsigned int iLenTemp;
		iLenTemp = wcslen(cCommand);
		if (cCommand[iLenTemp-1] == '\n')
			cCommand[iLenTemp-1] = '\0';
		iLenTemp = wcslen(cValue);
		if (cValue[iLenTemp-1] == '\n')
				cValue[iLenTemp-1] = '\0';
		iLenTemp = wcslen(cOptional);
		if (cOptional[iLenTemp-1] == '\n')
				cOptional[iLenTemp-1] = '\0';

		/* Process 'file' command (creates a file) */
		if (!_wcsicmp(cCommand, L"file")) {
			
			/* If 'undo' mode is on, remove the file, else create it */
			if (bUndo) {
				if (!DeleteFile(cValue)) {
					wprintf(L"Error: Removing file %s failed\n", cValue);
				} else {
					wprintf(L"Success: File %s successfully removed\n", cValue);
				}

			} else {

			FILE* fTemp;
			_wfopen_s(&fTemp, cValue, L"w");

			if (fTemp)
				wprintf(L"Success: File %s created\n", cValue);
			else
				wprintf(L"Error: File %s could not be created\n", cValue);
			
			/* If the optional parameter has data, this is content for the file */
			if (cOptional[0] != '\0')
				fwprintf(fTemp, cOptional);
				fclose(fTemp);
			}

		/* Process 'registry' command lines (creates registry keys */
		} else if (!_wcsicmp(cCommand, L"registry")) {


			/* Convert data into which key is being referenced */
			HKEY hKey;

			if (wcsstr(cValue, L"HKEY_CLASSES_ROOT"))
				hKey = HKEY_CLASSES_ROOT;
			else if (wcsstr(cValue, L"HKEY_CURRENT_CONFIG"))
				hKey = HKEY_CURRENT_CONFIG;	
			else if (wcsstr(cValue, L"HKEY_CURRENT_USER"))
				hKey = HKEY_CURRENT_USER;	
			else if (wcsstr(cValue, L"HKEY_LOCAL_MACHINE"))
				hKey = HKEY_LOCAL_MACHINE;
			else if (wcsstr(cValue, L"HKEY_USERS"))
				hKey = HKEY_USERS;
				
			/* Variable to now hold subkey */
			wchar_t* wSubKey = wcschr(cValue, L'\\');
			wSubKey++;
			
			/* If undo mode is active, delete the key */
			if (bUndo) {

				/* If a value is defined, only delete that */
				if (cOptional[0] != '\0') {

					/* Just the value, not value|data */
					wchar_t* wKeyValue = wcschr(cOptional, L'|');
					wKeyValue[0] = '\0';

					/* hKey_Opened is handle to open key */
					HKEY hKey_Opened = NULL;
					RegOpenKey(hKey, wSubKey, &hKey_Opened);

					if(!RegDeleteValue(hKey_Opened, cOptional))
						wprintf(L"Success: Registry value %s in key %s removed\n", cOptional, cValue);
					else
						wprintf(L"Error: Registry value %s in key %s could not be removed\n", cOptional, cValue);

					/* Check if key has any values left over */

					DWORD dSubKeys = NULL, dValues = NULL;
					RegQueryInfoKey(hKey_Opened, NULL, NULL, NULL, &dSubKeys, NULL, NULL, &dValues, NULL, NULL, NULL, NULL);

					/* Size of 'Default' value in key - 0 indicates '(Not set)' */
					DWORD lpdDefaultSize = 0;
					RegQueryValueEx(hKey_Opened, NULL, NULL, NULL, NULL, &lpdDefaultSize);

					if (!dSubKeys && !dValues && !lpdDefaultSize) {
			
						wprintf(L"Info: No remaining sub keys, values and no set default, deleting key...\n");

						if(!RegDeleteKey(hKey, wSubKey))
							wprintf(L"Success: Registry key %s removed\n", cValue);
						else
							wprintf(L"Error: Registry key %s could not be removed\n", cValue);
					
					}
				
				/* Else, delete the whole key */
				} else {

					if(!RegDeleteKey(hKey, wSubKey))
						wprintf(L"Success: Registry key %s removed\n", cValue);
					else
						wprintf(L"Error: Registry key %s could not be removed\n", cValue);

				}

			} else {

			/* Attempt to create key */
				if (!RegCreateKeyEx(hKey, wSubKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL))
					wprintf(L"Success: Registry key %s created\n", cValue);
				else
					wprintf(L"Error: Registry key %s could not be created\n", cValue);

				/* If optional parameter entered, add value & data (data is delimitered from value by | character) */
				if (cOptional[0] != '\0') {
					wchar_t* wKeyValue = wcschr(cOptional, L'|');
					wKeyValue[0] = '\0';
					wKeyValue++;
					RegSetKeyValue(hKey, NULL, cOptional, REG_SZ, wKeyValue, wcslen(wKeyValue)*2);
				}
			}
		
		/* 'process' command (creates a process with a certain name) 
			This is done by copying self to a temp folder with specified name and running */
		} else if (!bUndo && !_wcsicmp(cCommand, L"process")) {	

			/* Keep active is set, we don't want child process terminating with parent */
			bKeepActive = true;

			/* Convert argument 1 to wide char pointer */ 
			wchar_t w[MAX_PATH]; 
			size_t size_of_w = sizeof(w); 
			mbstowcs_s(&size_of_w, w, argv[0], MAX_PATH); 
			LPWSTR pFile = w; 

			/* Create path for temp executable */
			wchar_t wTempPath[MAX_PATH];
			GetTempPath(MAX_PATH, wTempPath);

			wcsncat_s(wTempPath, MAX_PATH, cValue, sizeof(cValue));

			/* Copy self to temp path with specified name */
			CopyFile(pFile, wTempPath, FALSE);

			/* Now add the 'skeleton' parameter */
			wchar_t* wPreArgvAddition = wcschr(wTempPath, L'\0');
			wcsncat_s(wTempPath, MAX_PATH, L" !skeleton!\0", 12);

			STARTUPINFO si;
			PROCESS_INFORMATION pi;

			ZeroMemory( &si, sizeof(si) );
			si.cb = sizeof(si);
			ZeroMemory( &pi, sizeof(pi) );
	
			/* Job object hack to ensure 'child process' is terminated when the main one closes */
			HANDLE ghJob = CreateJobObject( NULL, NULL);
			JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
			jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
			SetInformationJobObject( ghJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));

			if (!CreateProcess(NULL, wTempPath, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
				wprintf(L"Error: Process %s could not be created\n", cValue);
			else {
				AssignProcessToJobObject(ghJob, pi.hProcess);
				wprintf(L"Success: Process %s created\n", cValue);
			}
			
		/* Process 'mutex' command (creates mutex) */
		} else if (!bUndo && !_wcsicmp(cCommand, L"mutex")) {

			/* Mutex remains open with process */
			bKeepActive = true;

			/* Create mutex */
			if (CreateMutex(NULL, TRUE, cValue))
				wprintf(L"Success: Mutex %s created\n", cValue);
			else
				wprintf(L"Error: Mutex %s could not be created\n", cValue);

		} else if (!bUndo) {
			/* Supress these messages in undo mode */
			printf("Info: Ignoring invalid configuration entry\n");
		}

		/* Clear memory after each iteration */
		memset(&cCommand, 0, sizeof(cCommand));
		memset(&cValue, 0, sizeof(cValue));
		memset(&cOptional, 0, sizeof(cOptional));
	}

	/* Close file handle */
	fclose(fp);

	/* If keep active is required, keep the process running */
	if (bKeepActive) {
		printf("Info: Process will keep running to maintain mutex & subprocesses, Ctrl+C to exit\n");

		for (;;)
			Sleep(10000);
	}

	return 0;
}

