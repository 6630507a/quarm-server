#pragma once

#include <cstdlib>
#include <fstream>

// Optional, local-only control for process supervisors without a console. The
// operator supplies a private path per process; no listener or default is added.
inline bool LocalShutdownRequested()
{
    const char *file = std::getenv("EQEMU_SHUTDOWN_FILE");
    return file && *file && std::ifstream(file).good();
}
