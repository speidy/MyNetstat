// MyNetstat.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "NetworkConnections.h"


int main()
{
	NetworkConnections *nc = new NetworkConnections();
	nc->BuildConnectionsTable();
	nc->PrintConnections();
	delete nc;

	return 0;
}

