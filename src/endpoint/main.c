#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define VS_ED_CFG	"/data/vs-ep-cfg"

void vs_signal_process()
{
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
}

int main(int argc, char *argv[])
{
	vs_signal_process();

}
