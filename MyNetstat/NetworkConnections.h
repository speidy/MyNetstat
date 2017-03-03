#pragma once
#include <iphlpapi.h>


using namespace std;

class NetworkConnections
{
public:
	enum ConnectionType
	{
		UDP,
		TCP
	};
	enum IPVersion
	{
		IPv4,
		IPv6
	};
	struct ConnectionEntry
	{
		ConnectionType	connectionType;
		IPVersion		ipVersion;
		string			localAddress;
		uint16_t		localPort;
		string			remoteAddress;
		uint16_t		remotePort;
		string			connectionSate;
		uint32_t		ownerPid;
		wstring			serviceName;
		string			creationTimestamp;
	};

	NetworkConnections();
	~NetworkConnections();
	void buildConnectionsTable();
	vector<ConnectionEntry> getConnectionsTable() const;
	void printConnections();
private:
	typedef decltype(&GetExtendedTcpTable) PGetExtendedTcpTable;
	typedef decltype(&GetExtendedUdpTable) PGetExtendedUdpTable;
	typedef decltype(&GetTcpTable) PGetTcpTable;
	typedef decltype(&GetUdpTable) PGetUdpTable;
	typedef NTSTATUS(WINAPI *PAllocateAndGetTcpExTableFromStack) \
		(PVOID *ppTcpTable, bool bOrder, HANDLE hHeap, DWORD dwAllocFlags, DWORD dwFamily);
	typedef NTSTATUS(WINAPI *PAllocateAndGetUdpExTableFromStack) \
		(PVOID *ppUdpTable, bool bOrder, HANDLE hHeap, DWORD dwAllocFlags, DWORD dwFamily);


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
	void initializeHelperLibs();
	void deinitializeHelperLibs() const;
	void buildConnectionsTableNoPid();
	void buildConnectionsTableWin2000();
	static string connectionStateAsString(DWORD state);
	static string timestampAsString(const LARGE_INTEGER& li_create_timestamp);
	static string ipAddressAsString(IPVersion ver, PVOID addr);
	wstring getSerivceNameByTag(ULONG pid, ULONG serviceTag) const;
	
private:
	vector<ConnectionEntry> m_ConnectionTable;
	HMODULE m_hIpHlpApi;
	HMODULE m_hAdvApi32;
	PGetExtendedTcpTable m_pfnGetExtendedTcpTable;
	PGetExtendedUdpTable m_pfnGetExtendedUdpTable;
	PGetTcpTable m_pfnGetTcpTable;
	PGetUdpTable m_pfnGetUdpTable;
	PAllocateAndGetTcpExTableFromStack m_pfnAllocateAndGetTcpExTableFromStack;
	PAllocateAndGetUdpExTableFromStack m_pfnAllocateAndGetUdpExTableFromStack;
	PQueryTagInformation m_pfnQueryTagInformation;
};
