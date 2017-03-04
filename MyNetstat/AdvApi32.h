#pragma once
using namespace std;

class AdvApi32 {
public:
	AdvApi32();
	~AdvApi32();
	wstring getSerivceNameByTag(ULONG pid, ULONG serviceTag) const;

private:
	typedef enum _SC_SERVICE_TAG_QUERY_TYPE
	{
		ServiceNameFromTagInformation = 1,
		ServiceNamesReferencingModuleInformation,
		ServiceNameTagMappingInformation
	} SC_SERVICE_TAG_QUERY_TYPE, *PSC_SERVICE_TAG_QUERY_TYPE;

	typedef struct _SC_SERVICE_TAG_QUERY
	{
		ULONG ProcessId;
		ULONG ServiceTag;
		ULONG Unknown;
		PVOID Buffer;
	} SC_SERVICE_TAG_QUERY, *PSC_SERVICE_TAG_QUERY;

	typedef ULONG(NTAPI *PQueryTagInformation)(
		__in PVOID Unknown,
		__in SC_SERVICE_TAG_QUERY_TYPE QueryType,
		__inout PSC_SERVICE_TAG_QUERY Query
		);

private:
	HMODULE m_hAdvApi32;
	PQueryTagInformation m_pfnQueryTagInformation;
};
