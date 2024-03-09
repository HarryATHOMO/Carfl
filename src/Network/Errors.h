#pragma once

namespace Network
{
static constexpr int INVALID_SOCKET = -1;
static constexpr int SOCKET_ERROR = -1;

namespace Errors
{
int Get();
enum {
#ifdef _WIN32
    AGAIN = WSATRY_AGAIN,
    WOULDBLOCK = WSAEWOULDBLOCK,
    INPROGRESS = WSAEINPROGRESS,
    INTR = WSAEINTR,
#else
    AGAIN = EAGAIN,
    WOULDBLOCK = EWOULDBLOCK,
    INPROGRESS = EINPROGRESS,
    INTR = EINTR,
#endif
};
}
}