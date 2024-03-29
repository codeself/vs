#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

void vs_signal_process()
{
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
}

int main(int argc, char *argv[])
{
	vs_signal_process();
	
	if (vs_cfg_parse(VS_ED_CFG))
		return VS_ERR;
    
    if (log_init())
        return VS_ERR;

    if (communication_init())
        return VS_ERR;

	return VS_OK;	
}
