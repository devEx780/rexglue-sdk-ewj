/**
 * @file        tests/unit/core/socket_close_test.cpp
 * @brief       Guest sockets use Winsock/console semantics. On POSIX hosts: closing must wake a
 *              blocked receiver, FIONBIO must make the socket non-blocking, and SOL_SOCKET options
 *              given with Winsock codes must reach the host socket.
 */

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

#include <catch2/catch_test_macros.hpp>

#include <rex/net/socket.h>

#if !defined(_WIN32)
#include <cerrno>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

int BoundUdpSocket() {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  return fd;
}

// Guest memory is big-endian.
void StoreBigEndian(uint8_t* out, uint32_t value) {
  out[0] = uint8_t(value >> 24);
  out[1] = uint8_t(value >> 16);
  out[2] = uint8_t(value >> 8);
  out[3] = uint8_t(value);
}

}  // namespace

TEST_CASE("socket_close wakes a thread blocked in recvfrom", "[net]") {
  int fd = BoundUdpSocket();
  REQUIRE(fd >= 0);

  std::atomic<bool> returned{false};
  std::thread receiver([&] {
    char buf[16];
    recvfrom(fd, buf, sizeof(buf), 0, nullptr, nullptr);
    returned = true;
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  rex::net::socket_close(fd);
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (!returned && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  bool woke = returned;
  if (!woke) {
    shutdown(fd, SHUT_RDWR);
  }
  receiver.join();
  REQUIRE(woke);
}

TEST_CASE("Winsock FIONBIO makes a socket non-blocking", "[net]") {
  int fd = BoundUdpSocket();
  REQUIRE(fd >= 0);
  uint8_t enable[4];
  StoreBigEndian(enable, 1);
  REQUIRE(rex::net::socket_ioctl(fd, 0x8004667E, enable) == 0);

  char buf[16];
  errno = 0;
  REQUIRE(recvfrom(fd, buf, sizeof(buf), 0, nullptr, nullptr) == -1);
  REQUIRE((errno == EAGAIN || errno == EWOULDBLOCK));
  close(fd);
}

TEST_CASE("Winsock SOL_SOCKET options reach the host socket", "[net]") {
  int fd = BoundUdpSocket();
  REQUIRE(fd >= 0);
  uint8_t on[4];
  StoreBigEndian(on, 1);
  // level 0xFFFF = Winsock SOL_SOCKET, 0x0004 = SO_REUSEADDR, 0x0020 = SO_BROADCAST.
  REQUIRE(rex::net::socket_setopt(fd, 0xFFFF, 0x0004, on, 4) == 0);
  REQUIRE(rex::net::socket_setopt(fd, 0xFFFF, 0x0020, on, 4) == 0);

  int value = 0;
  socklen_t len = sizeof(value);
  getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, &len);
  CHECK(value != 0);
  value = 0;
  getsockopt(fd, SOL_SOCKET, SO_BROADCAST, &value, &len);
  CHECK(value != 0);
  close(fd);
}
#endif
