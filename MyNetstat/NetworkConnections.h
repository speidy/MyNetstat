#pragma once
#include <iphlpapi.h>
#include <vector>
#include <string>
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
		ConnectionType connectionType;
		IPVersion		ipVersion;
		string			localAddress;
		DWORD			localPort;
		string			remoteAddress;
		DWORD			remotePort;
		string			connectionSate;
		DWORD			ownerPid;
		wstring		serviceName;
		string			creationTimestamp;

		ConnectionEntry(ConnectionType connection_type, IPVersion ip_version, const string& local_address,
			DWORD local_port, const string& remote_address, DWORD remote_port, const string& connection_sate,
			DWORD owner_pid, const wstring& service_name, const string& creation_timestamp)
			: connectionType(connection_type),
			ipVersion(ip_version),
			localAddress(local_address),
			localPort(local_port),
			remoteAddress(remote_address),
			remotePort(remote_port),
			connectionSate(connection_sate),
			ownerPid(owner_pid),
			serviceName(service_name),
			creationTimestamp(creation_timestamp)
		{
		}
	};

	NetworkConnections();
	~NetworkConnections();
	void BuildConnectionsTable();
	vector<ConnectionEntry> GetConnectionsTable();
	void PrintConnections();

private:
	typedef decltype(&GetExtendedTcpTable) PGetExtendedTcpTable;
	typedef decltype(&GetExtendedUdpTable) PGetExtendedUdpTable;
	typedef decltype(&GetTcpTable) PGetTcpTable;
	typedef decltype(&GetUdpTable) PGetUdpTable;

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
	void BuildConnectionsTableWin2000();
	void initializeHelperLibs();
	static string ConnectionStateAsString(DWORD state);
	static string timestampAsString(const LARGE_INTEGER& li_create_timestamp);
	static string ipAddressAsString(IPVersion ver, const void *addr);
	wstring getSerivceNameByTag(ULONG pid, ULONG serviceTag) const;

private:
	vector<ConnectionEntry> m_ConnectionTable;
	PGetExtendedTcpTable m_pfnGetExtendedTcpTable;
	PGetExtendedUdpTable m_pfnGetExtendedUdpTable;
	PGetTcpTable m_pfnGetTcpTable;
	PGetUdpTable m_pfnGetUdpTable;
	PQueryTagInformation m_pfnQueryTagInformation;
	bool m_IsNewApiSupported;
};
