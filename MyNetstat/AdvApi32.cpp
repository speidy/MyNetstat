#include "stdafx.h"
#include "advapi32.h"

AdvApi32::AdvApi32() : m_hAdvApi32(nullptr), m_pfnQueryTagInformation(nullptr)
{
	m_hAdvApi32 = LoadLibrary(L"advapi32.dll");
	m_pfnQueryTagInformation = reinterpret_cast<AdvApi32::PQueryTagInformation>(GetProcAddress(m_hAdvApi32, "I_QueryTagInformation"));
}

AdvApi32::~AdvApi32()
{
	FreeLibrary(m_hAdvApi32);
}

/* 
This function returns the service name corresponds the pid and service tag

This function uses the advapi32!I_QueryTagInformation undocumented function.
reference: http://www.alex-ionescu.com/?p=52
*/
wstring AdvApi32::getSerivceNameByTag(ULONG pid, ULONG serviceTag) const
{
	SC_SERVICE_TAG_QUERY query;
	wstring serviceName;

	if (m_pfnQueryTagInformation)
	{
		query.ProcessId = pid;
		query.ServiceTag = serviceTag;
		query.Unknown = 0;
		query.Buffer = nullptr;

		m_pfnQueryTagInformation(nullptr, ServiceNameFromTagInformation, &query);

		if (query.Buffer)
		{
			serviceName = wstring(static_cast<const wchar_t*>(query.Buffer));
		}
		LocalFree(query.Buffer);
	} 

	return serviceName;
}
