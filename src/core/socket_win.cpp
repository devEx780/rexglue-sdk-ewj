#include <rex/net/socket.h>
#include <rex/platform.h>

static_assert(REX_PLATFORM_WIN32, "This file is Windows-only");

#include "platform_win.h"

#include <WinSock2.h>

namespace rex::net {

int socket_close(SocketHandle handle) {
  return closesocket(static_cast<SOCKET>(handle));
}

int socket_ioctl(SocketHandle handle, uint32_t cmd, uint8_t* arg) {
  return ioctlsocket(static_cast<SOCKET>(handle), cmd, reinterpret_cast<u_long*>(arg));
}

int socket_setopt(SocketHandle handle, uint32_t level, uint32_t optname, const uint8_t* value,
                  uint32_t len) {
  // Winsock codes are native here.
  return setsockopt(static_cast<SOCKET>(handle), int(level), int(optname),
                    reinterpret_cast<const char*>(value), int(len));
}

}  // namespace rex::net
