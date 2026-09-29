#include <rex/net/socket.h>
#include <rex/platform.h>

static_assert(REX_PLATFORM_LINUX || REX_PLATFORM_MAC, "This file is POSIX-only");

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace rex::net {

namespace {

// Guest values are big-endian 32-bit integers.
uint32_t LoadGuestU32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

// Winsock codes titles use (they differ from the POSIX ones).
constexpr uint32_t kWinFionbio = 0x8004667E;
constexpr uint32_t kWinSolSocket = 0xFFFF;

int PosixSocketOption(uint32_t win_optname) {
  switch (win_optname) {
    case 0x0004: return SO_REUSEADDR;
    case 0x0008: return SO_KEEPALIVE;
    case 0x0020: return SO_BROADCAST;
    case 0x1001: return SO_SNDBUF;
    case 0x1002: return SO_RCVBUF;
    case 0x1005: return SO_SNDTIMEO;
    case 0x1006: return SO_RCVTIMEO;
    default: return -1;
  }
}

}  // namespace

int socket_close(SocketHandle handle) {
  // Unlike closesocket on Windows (and the console), close() does not wake a thread blocked in
  // recv on this socket. Titles stop their network thread exactly that way, so shut it down first.
  shutdown(static_cast<int>(handle), SHUT_RDWR);
  return close(static_cast<int>(handle));
}

int socket_ioctl(SocketHandle handle, uint32_t cmd, uint8_t* arg) {
  int fd = static_cast<int>(handle);
  if (cmd == kWinFionbio) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    flags = LoadGuestU32(arg) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return fcntl(fd, F_SETFL, flags) < 0 ? -1 : 0;
  }
  return ioctl(fd, cmd, arg);
}

int socket_setopt(SocketHandle handle, uint32_t level, uint32_t optname, const uint8_t* value,
                  uint32_t len) {
  int fd = static_cast<int>(handle);
  if (level != kWinSolSocket) {
    return setsockopt(fd, int(level), int(optname), value, len);
  }
  int name = PosixSocketOption(optname);
  if (name < 0 || len < 4) {
    return -1;
  }
  uint32_t v = LoadGuestU32(value);
  if (name == SO_SNDTIMEO || name == SO_RCVTIMEO) {
    // Winsock: milliseconds; POSIX: timeval.
    timeval tv{time_t(v / 1000), suseconds_t((v % 1000) * 1000)};
    return setsockopt(fd, SOL_SOCKET, name, &tv, sizeof(tv));
  }
  int iv = int(v);
  return setsockopt(fd, SOL_SOCKET, name, &iv, sizeof(iv));
}

}  // namespace rex::net
