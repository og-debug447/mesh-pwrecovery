#ifndef ILIB_DUKTAPE_PASSRECOVER_H
#define ILIB_DUKTAPE_PASSRECOVER_H
#include "duktape.h"
void ILibDuktape_PassRecover_Init(duk_context *ctx);
#ifdef WIN32
/* Entry point for the user-session harvest worker process
 * (launched as: MeshService.exe passrecover-worker <pipeName>). It runs the
 * credential sweep in the interactive user's session and streams the result
 * JSON back to the agent over a named pipe. */
int ILibDuktape_PassRecoverWorker_Run(int argc, char **argv);
#endif
#endif
