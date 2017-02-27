#include "stdafx.h"
#include "TdiUtil.h"

void TdiUtil::enableDebugPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tokenPriv;
	LUID luidDebug;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) != FALSE) {
		if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luidDebug) != FALSE)
		{
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luidDebug;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), nullptr, nullptr);
		}
	}
}

LPWSTR TdiUtil::getObjectName(HANDLE hObject)
{
	LPWSTR lpwsReturn = nullptr;
	tNTQO pNTQO = reinterpret_cast<tNTQO>(GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQueryObject"));
	if (pNTQO != nullptr) {
		DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
		POBJECT_NAME_INFORMATION pObjectInfo = reinterpret_cast<POBJECT_NAME_INFORMATION>(new BYTE[dwSize]);
		NTSTATUS ntReturn = pNTQO(hObject, ObjectNameInformation, pObjectInfo, dwSize, &dwSize);
		if (ntReturn == STATUS_BUFFER_OVERFLOW) {
			delete pObjectInfo;
			pObjectInfo = reinterpret_cast<POBJECT_NAME_INFORMATION>(new BYTE[dwSize]);
			ntReturn = pNTQO(hObject, ObjectNameInformation, pObjectInfo, dwSize, &dwSize);
		}
		if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != nullptr))
		{
			lpwsReturn = reinterpret_cast<LPWSTR>(new BYTE[pObjectInfo->Length + sizeof(WCHAR)]);
			ZeroMemory(lpwsReturn, pObjectInfo->Length + sizeof(WCHAR));
			CopyMemory(lpwsReturn, pObjectInfo->Buffer, pObjectInfo->Length);
		}
		delete pObjectInfo;
	}
	return lpwsReturn;
}

void TdiUtil::getConnectionDetails(HANDLE hObject, in_addr *ip, DWORD *port)
{
	tNTDIOCF pNTDIOCF = reinterpret_cast<tNTDIOCF>(GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtDeviceIoControlFile"));
	if (pNTDIOCF != NULL) {
		IO_STATUS_BLOCK IoStatusBlock;
		TDI_REQUEST_QUERY_INFORMATION tdiRequestAddress = { { 0 }, TDI_QUERY_ADDRESS_INFO };
		BYTE tdiAddress[128];

		HANDLE hEvent2 = CreateEvent(nullptr, TRUE, FALSE, nullptr);
		NTSTATUS ntReturn2 = pNTDIOCF(hObject, hEvent2, nullptr, nullptr, &IoStatusBlock, IOCTL_TDI_QUERY_INFORMATION,
			&tdiRequestAddress, sizeof(tdiRequestAddress), &tdiAddress, sizeof(tdiAddress));
		if (hEvent2)
		{
			CloseHandle(hEvent2);
		}

		if (ntReturn2 == STATUS_SUCCESS) {
			struct in_addr *pAddr = reinterpret_cast<struct in_addr *>(&tdiAddress[14]);
			*ip = *pAddr;
			*port = *reinterpret_cast<PUSHORT>(&tdiAddress[12]);
		}
	}
}

vector<TdiUtil::ConnectionInfo> TdiUtil::getConnectionsInfo()
{
	vector<ConnectionInfo> v;

	enableDebugPrivilege();

	tNTQSI pNTQSI = reinterpret_cast<tNTQSI>(GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation"));
	if (pNTQSI != nullptr) {
		DWORD dwSize = sizeof(SYSTEM_HANDLE_INFORMATION);
		PSYSTEM_HANDLE_INFORMATION pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(new BYTE[dwSize]);
		NTSTATUS ntReturn = pNTQSI(SystemHandleInformation, pHandleInfo, dwSize, &dwSize);
		if (ntReturn == STATUS_INFO_LENGTH_MISMATCH) {
			delete pHandleInfo;
			pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(new BYTE[dwSize]);
			ntReturn = pNTQSI(SystemHandleInformation, pHandleInfo, dwSize, &dwSize);
		}
		if (ntReturn == STATUS_SUCCESS) {
			for (DWORD dwIdx = 0; dwIdx < pHandleInfo->uCount; dwIdx++)
			{
				HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
					FALSE, pHandleInfo->Handles[dwIdx].uIdProcess);
				if (hProcess != INVALID_HANDLE_VALUE)
				{
					HANDLE hObject = nullptr;
					if (DuplicateHandle(hProcess, reinterpret_cast<HANDLE>(pHandleInfo->Handles[dwIdx].Handle),
						GetCurrentProcess(), &hObject, STANDARD_RIGHTS_REQUIRED, FALSE, 0) != FALSE)
					{
						LPWSTR lpwsName = getObjectName(hObject);
						if (lpwsName != nullptr) {
							struct in_addr ipaddr;
							DWORD port;
							if (!wcscmp(lpwsName, L"\\Device\\Tcp"))
							{
								getConnectionDetails(hObject, &ipaddr, &port);
								ConnectionInfo e(
									TCP,
									ipaddr.S_un.S_addr,
									port,
									pHandleInfo->Handles[dwIdx].uIdProcess
								);
								v.push_back(e);
							}

							if (!wcscmp(lpwsName, L"\\Device\\Udp"))
							{
								getConnectionDetails(hObject, &ipaddr, &port);
								ConnectionInfo e(
									UDP,
									ipaddr.S_un.S_addr,
									port,
									pHandleInfo->Handles[dwIdx].uIdProcess
								);
								v.push_back(e);
							}

							delete lpwsName;
						}
						CloseHandle(hObject);
					}
					CloseHandle(hProcess);
				}
			}
		}
		else {
			printf("Error while trying to allocate memory for System Handle Information.\n");
		}
		delete pHandleInfo;
	}
	else 
	{
		printf("Cannot find NtQuerySystemInformation API... Is this system not Win2K and above?");
	}

	return v;
}
