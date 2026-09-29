/**
 * @file        net/socket.h
 * @brief       Platform-agnostic socket operations
 */
#pragma once

#include <cstdint>

namespace rex::net {

using SocketHandle = int64_t;
constexpr SocketHandle kInvalidSocket = -1;

int socket_close(SocketHandle handle);
int socket_ioctl(SocketHandle handle, uint32_t cmd, uint8_t* arg);
// setsockopt taking Winsock level/option codes and a guest (big-endian) value, as titles pass them.
int socket_setopt(SocketHandle handle, uint32_t level, uint32_t optname, const uint8_t* value,
                  uint32_t len);

}  // namespace rex::net
