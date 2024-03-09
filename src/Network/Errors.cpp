#include <cerrno>
#include "Errors.h"


namespace Network
{
namespace Errors
{
int Get()
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}
}
}

