#include "stdafx.h"
#include "NetworkConnections.h"
#include <sstream>
#include <iostream>
#include <iomanip>

static const string TCP_STATES_STR[] =
{
	"UNKNOWN",
	"CLOSED",
	"LISTEN",
	"SYN-SENT",
	"SYN-RECEIVED",
	"ESTABLISHED",
	"FIN-WAIT-1",
	"FIN-WAIT-2",
	"CLOSE-WAIT",
	"CLOSING",
	"LAST-ACK",
	"TIME-WAIT",
	"DELETE-TCB"
};

NetworkConnections::NetworkConnections() :
	m_pfnGetExtendedTcpTable(nullptr), m_pfnGetExtendedUdpTable(nullptr), m_pfnGetTcpTable(nullptr), 
	m_pfnGetUdpTable(nullptr), m_pfnAllocateAndGetTcpExTableFromStack(nullptr), m_pfnAllocateAndGetUdpExTableFromStack(nullptr),
	m_pfnQueryTagInformation(nullptr)
{
	initializeHelperLibs();
}

NetworkConnections::~NetworkConnections()
{
}

vector<NetworkConnections::ConnectionEntry> NetworkConnections::getConnectionsTable()
{
	buildConnectionsTable();
	return m_ConnectionTable;
}

void NetworkConnections::printConnections()
{
	/* print table header */
	cout << left << setw(10) << "Proto" << setw(17) << "Local Address" << setw(7) << "Port" << setw(17) <<
		"Remote Address" << setw(7) << "Port" << setw(15) << "State" << setw(7) << "PID" << setw(20) <<
		"Timestamp" << setw(15) << "Service Name" << endl;

	/* print connection entries */
	for (ConnectionEntry entry : m_ConnectionTable)
	{
		string ipVer = (entry.ipVersion == IPv4) ? "v4" : "v6";
		string proto = entry.connectionType == TCP ? "TCP" : "UDP";
		proto += ipVer;

		cout << left << setw(10) << proto << setw(17) << entry.localAddress << setw(7) << entry.localPort <<
			setw(17) << entry.remoteAddress << setw(7) << entry.remotePort << setw(15) << entry.connectionSate <<
			setw(7) << entry.ownerPid << setw(20) << entry.creationTimestamp << setw(15);
		wcout << entry.serviceName << endl;
	}

	cout << "Number of connections: " << m_ConnectionTable.size() << endl;

}

void NetworkConnections::buildConnectionsTableWin2000()
{
	if (!(m_pfnAllocateAndGetTcpExTableFromStack && m_pfnAllocateAndGetUdpExTableFromStack))
	{
		/* functions not available */
		buildConnectionsTableNoPid();
		return;
	}

	/* TCP Connections, IPv4 only */
	PMIB_TCPTABLE_OWNER_PID pTcpTable;

	if (ERROR_SUCCESS == m_pfnAllocateAndGetTcpExTableFromStack(reinterpret_cast<LPVOID *>(&pTcpTable), TRUE, GetProcessHeap(), 0, AF_INET))
	{
		for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i)
		{
			auto tcpRow = pTcpTable->table[i];
			ConnectionEntry e(
				TCP,
				IPv4,
				ipAddressAsString(IPv4, &tcpRow.dwLocalAddr),
				ntohs(tcpRow.dwLocalPort),
				ipAddressAsString(IPv4, &tcpRow.dwRemoteAddr),
				ntohs(tcpRow.dwRemotePort),
				connectionStateAsString(tcpRow.dwState),
				tcpRow.dwOwningPid,
				L"",
				""
			);
			m_ConnectionTable.push_back(e);
		}
		HeapFree(GetProcessHeap(), 0, pTcpTable);
	}

	/* UDP Connections, IPv4 only */
	PMIB_UDPTABLE_OWNER_PID pUdpTable;

	if (ERROR_SUCCESS == m_pfnAllocateAndGetUdpExTableFromStack(reinterpret_cast<LPVOID *>(&pUdpTable), TRUE, GetProcessHeap(), 0, AF_INET))
	{
		for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i)
		{
			auto udpRow = pUdpTable->table[i];
			ConnectionEntry e(
				UDP,
				IPv4,
				ipAddressAsString(IPv4, &udpRow.dwLocalAddr),
				ntohs(udpRow.dwLocalPort),
				"",
				0,
				"",
				udpRow.dwOwningPid,
				L"",
				""
			);
			m_ConnectionTable.push_back(e);
		}
		HeapFree(GetProcessHeap(), 0, pTcpTable);
	}
}

void NetworkConnections::buildConnectionsTable()
{
	/* clear old entries */
	m_ConnectionTable.clear();

	if (!(m_pfnGetExtendedTcpTable && m_pfnGetExtendedUdpTable))
	{
		buildConnectionsTableWin2000();
		return;
	}

	/* TCP Connections, IPv4 */
	PMIB_TCPTABLE_OWNER_MODULE pTcpTable;
	DWORD cbTcpTable;

	cbTcpTable = 0;
	if (ERROR_INSUFFICIENT_BUFFER == m_pfnGetExtendedTcpTable(nullptr, &cbTcpTable, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0))
	{
		pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_MODULE>(new byte[cbTcpTable]);
		if (NO_ERROR == m_pfnGetExtendedTcpTable(pTcpTable, &cbTcpTable, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0))
		{
			for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i)
			{
				MIB_TCPROW_OWNER_MODULE tcpRow = pTcpTable->table[i];
				ConnectionEntry e(
					TCP,
					IPv4,
					ipAddressAsString(IPv4, &tcpRow.dwLocalAddr),
					ntohs(tcpRow.dwLocalPort),
					ipAddressAsString(IPv4, &tcpRow.dwRemoteAddr),
					ntohs(tcpRow.dwRemotePort),
					connectionStateAsString(tcpRow.dwState),
					tcpRow.dwOwningPid,
					getSerivceNameByTag(tcpRow.dwOwningPid, *reinterpret_cast<PULONG>(tcpRow.OwningModuleInfo)),
					timestampAsString(tcpRow.liCreateTimestamp)
				);
				m_ConnectionTable.push_back(e);
			}
		}
		if (pTcpTable)
		{
			delete pTcpTable;
		}
	}

	/* TCP Connections, IPv6 */
	PMIB_TCP6TABLE_OWNER_MODULE pTcp6Table;
	DWORD cbTcp6Table;

	cbTcp6Table = 0;
	if (ERROR_INSUFFICIENT_BUFFER == m_pfnGetExtendedTcpTable(nullptr, &cbTcp6Table, TRUE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0))
	{
		pTcp6Table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_MODULE>(new byte[cbTcp6Table]);
		if (NO_ERROR == m_pfnGetExtendedTcpTable(pTcp6Table, &cbTcp6Table, TRUE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0))
		{
			for (DWORD i = 0; i < pTcp6Table->dwNumEntries; ++i)
			{
				MIB_TCP6ROW_OWNER_MODULE tcpRow = pTcp6Table->table[i];
				ConnectionEntry e(
					TCP,
					IPv6,
					ipAddressAsString(IPv6, tcpRow.ucLocalAddr),
					ntohs(tcpRow.dwLocalPort),
					ipAddressAsString(IPv6, tcpRow.ucRemoteAddr),
					ntohs(tcpRow.dwRemotePort),
					connectionStateAsString(tcpRow.dwState),
					tcpRow.dwOwningPid,
					getSerivceNameByTag(tcpRow.dwOwningPid, *reinterpret_cast<PULONG>(tcpRow.OwningModuleInfo)),
					timestampAsString(tcpRow.liCreateTimestamp)
				);
				m_ConnectionTable.push_back(e);
			}
		}
		if (pTcp6Table)
		{
			delete pTcp6Table;
		}
	}

	/* UDP Connections, IPv4 */
	PMIB_UDPTABLE_OWNER_MODULE pUdpTable;
	DWORD cbUdpTable;

	cbUdpTable = 0;
	if (ERROR_INSUFFICIENT_BUFFER == m_pfnGetExtendedUdpTable(nullptr, &cbUdpTable, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0))
	{
		pUdpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_MODULE>(new byte[cbUdpTable]);
		if (NO_ERROR == m_pfnGetExtendedUdpTable(pUdpTable, &cbUdpTable, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0))
		{
			for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i)
			{
				MIB_UDPROW_OWNER_MODULE udpRow = pUdpTable->table[i];
				ConnectionEntry e(
					UDP,
					IPv4,
					ipAddressAsString(IPv4, &udpRow.dwLocalAddr),
					ntohs(udpRow.dwLocalPort),
					"",
					0,
					"",
					udpRow.dwOwningPid,
					getSerivceNameByTag(udpRow.dwOwningPid, *reinterpret_cast<PULONG>(udpRow.OwningModuleInfo)),
					timestampAsString(udpRow.liCreateTimestamp)
				);
				m_ConnectionTable.push_back(e);
			}
		}
		if (pUdpTable)
		{
			delete pUdpTable;
		}
	}

	/* UDP Connections, IPv6 */
	PMIB_UDP6TABLE_OWNER_MODULE pUdp6Table;
	DWORD cbUdp6Table;

	cbUdp6Table = 0;
	if (ERROR_INSUFFICIENT_BUFFER == m_pfnGetExtendedUdpTable(nullptr, &cbUdp6Table, TRUE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0))
	{
		pUdp6Table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_MODULE>(new byte[cbUdp6Table]);
		if (NO_ERROR == m_pfnGetExtendedUdpTable(pUdp6Table, &cbUdpTable, TRUE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0))
		{
			for (DWORD i = 0; i < pUdp6Table->dwNumEntries; ++i)
			{
				MIB_UDP6ROW_OWNER_MODULE udpRow = pUdp6Table->table[i];
				ConnectionEntry e(
					UDP,
					IPv6,
					ipAddressAsString(IPv6, udpRow.ucLocalAddr),
					udpRow.dwLocalPort,
					"",
					0,
					"",
					udpRow.dwOwningPid,
					getSerivceNameByTag(udpRow.dwOwningPid, *reinterpret_cast<PULONG>(udpRow.OwningModuleInfo)),
					timestampAsString(udpRow.liCreateTimestamp)
				);
				m_ConnectionTable.push_back(e);
			}
		}
		if (pUdp6Table)
		{
			delete pUdp6Table;
		}
	}
}

void NetworkConnections::initializeHelperLibs()
{
	auto hIpHlpApi = LoadLibrary(L"iphlpapi.dll");
	m_pfnGetExtendedTcpTable = reinterpret_cast<PGetExtendedTcpTable>(GetProcAddress(hIpHlpApi, "GetExtendedTcpTable"));
	m_pfnGetExtendedUdpTable = reinterpret_cast<PGetExtendedUdpTable>(GetProcAddress(hIpHlpApi, "GetExtendedUdpTable"));
	m_pfnGetTcpTable = reinterpret_cast<PGetTcpTable>(GetProcAddress(hIpHlpApi, "GetTcpTable"));
	m_pfnGetUdpTable = reinterpret_cast<PGetUdpTable>(GetProcAddress(hIpHlpApi, "GetUdpTable"));
	m_pfnAllocateAndGetTcpExTableFromStack = reinterpret_cast<PAllocateAndGetTcpExTableFromStack>(GetProcAddress(hIpHlpApi, "AllocateAndGetTcpExTableFromStack"));
	m_pfnAllocateAndGetUdpExTableFromStack = reinterpret_cast<PAllocateAndGetUdpExTableFromStack>(GetProcAddress(hIpHlpApi, "AllocateAndGetUdpExTableFromStack"));


	auto hAdvApi32 = LoadLibrary(L"advapi32.dll");
	m_pfnQueryTagInformation = reinterpret_cast<PQueryTagInformation>(GetProcAddress(hAdvApi32, "I_QueryTagInformation"));
}

void NetworkConnections::buildConnectionsTableNoPid()
{
	if (!(m_pfnGetTcpTable && m_pfnGetUdpTable))
	{
		return;
	}

	/* TCP Connections, IPv4 only */
	PMIB_TCPTABLE pTcpTable;
	DWORD cbTcpTable;

	cbTcpTable = 0;
	if (ERROR_INSUFFICIENT_BUFFER == m_pfnGetTcpTable(nullptr, &cbTcpTable, TRUE))
	{
		pTcpTable = reinterpret_cast<PMIB_TCPTABLE>(new byte[cbTcpTable]);
		if (NO_ERROR == m_pfnGetTcpTable(pTcpTable, &cbTcpTable, TRUE))
		{
			for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i)
			{
				auto tcpRow = pTcpTable->table[i];
				ConnectionEntry e(
					TCP,
					IPv4,
					ipAddressAsString(IPv4, &tcpRow.dwLocalAddr),
					ntohs(tcpRow.dwLocalPort),
					ipAddressAsString(IPv4, &tcpRow.dwRemoteAddr),
					ntohs(tcpRow.dwRemotePort),
					connectionStateAsString(tcpRow.dwState),
					0,
					L"",
					""
				);
				m_ConnectionTable.push_back(e);
			}
		}
		if (pTcpTable)
		{
			delete pTcpTable;
		}
	}

	/* UDP Connections, IPv4 only */
	PMIB_UDPTABLE pUdpTable;
	DWORD cbUdpTable;

	cbUdpTable = 0;
	if (ERROR_INSUFFICIENT_BUFFER == m_pfnGetUdpTable(nullptr, &cbUdpTable, TRUE))
	{
		pUdpTable = reinterpret_cast<PMIB_UDPTABLE>(new byte[cbUdpTable]);
		if (NO_ERROR == m_pfnGetUdpTable(pUdpTable, &cbUdpTable, TRUE))
		{
			for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i)
			{
				auto udpRow = pUdpTable->table[i];
				ConnectionEntry e(
					UDP,
					IPv4,
					ipAddressAsString(IPv4, &udpRow.dwLocalAddr),
					udpRow.dwLocalPort,
					"",
					0,
					"",
					0,
					L"",
					""
				);
				m_ConnectionTable.push_back(e);
			}
		}
		if (pUdpTable)
		{
			delete pUdpTable;
		}
	}

}

string NetworkConnections::timestampAsString(const LARGE_INTEGER& ts)
{
	ostringstream timestamp;
	FILETIME ft;
	SYSTEMTIME st;

	ft.dwLowDateTime = ts.LowPart;
	ft.dwHighDateTime = ts.HighPart;
	FileTimeToSystemTime(&ft, &st);

	timestamp << st.wDay << "-" << st.wMonth << "-" << st.wYear << " " <<
		st.wHour << ":" << st.wMinute << ":" << st.wSecond;

	return timestamp.str();
}

string NetworkConnections::ipAddressAsString(IPVersion ver, const void *addr)
{
	ostringstream ipAddress;


	switch (ver)
	{
	case IPv4:
		DWORD ip;
		unsigned char bytes[4];
		ip = *(DWORD *)addr;
		bytes[0] = ip & 0xFF;
		bytes[1] = (ip >> 8) & 0xFF;
		bytes[2] = (ip >> 16) & 0xFF;
		bytes[3] = (ip >> 24) & 0xFF;
		ipAddress << static_cast<unsigned int>(bytes[0]) << "." <<
			static_cast<unsigned int>(bytes[1]) << "." <<
			static_cast<unsigned int>(bytes[2]) << "." <<
			static_cast<unsigned int>(bytes[3]);
		break;
	case IPv6:
		UCHAR *ip6 = (UCHAR *)addr;
		ipAddress << "[" << hex << (int)ip6[0] << hex << (int)ip6[1] << ":" << hex << (int)ip6[2] << hex << (int)ip6[3] << ":" <<
			hex << (int)ip6[4] << hex << (int)ip6[5] << ":" << hex << (int)ip6[6] << hex << (int)ip6[7] << ":" <<
			hex << (int)ip6[8] << hex << (int)ip6[9] << ":" << hex << (int)ip6[10] << hex << (int)ip6[11] << ":" <<
			hex << (int)ip6[12] << hex << (int)ip6[13] << ":" << hex << (int)ip6[14] << hex << (int)ip6[15]
			<< "]";
		break;
	}

	return ipAddress.str();
}

string NetworkConnections::connectionStateAsString(DWORD state)
{
	return TCP_STATES_STR[state];
}

wstring NetworkConnections::getSerivceNameByTag(ULONG pid, ULONG serviceTag) const
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
