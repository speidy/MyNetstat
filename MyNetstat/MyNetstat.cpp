// MyNetstat.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "NetworkConnections.h"
#include <iostream>


int main()
{
	NetworkConnections *nc = new NetworkConnections();
	nc->buildConnectionsTable();
	nc->printConnections();
	delete nc;
	
	return 0;
}

