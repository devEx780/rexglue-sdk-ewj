/**
 * Regression tests for XAM user-profile defaults.
 */

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <cstring>
#include <fstream>
#include <string>
#include <iterator>
#include <utility>
#include <thread>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rex/runtime.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xio.h>
#include <rex/system/xam/user_profile.h>
#include <rex/system/user_module.h>
#include <rex/system/xenumerator.h>
#include <rex/system/xthread.h>
#include <rex/ppc/func.h>

extern "C" void __imp__XamUserCreateStatsEnumerator(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__XamUserGetSigninState(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__XamUserGetXUID(PPCContext& ctx, uint8_t* base);
extern "C" void __imp__XamUserGetSigninInfo(PPCContext& ctx, uint8_t* base);

namespace rex::kernel::xam {
uint32_t XamUserReadProfileSettingsEx(uint32_t title_id, uint32_t user_index, uint32_t xuid_count,
                                      be<uint64_t>* xuids, uint32_t setting_count,
                                      be<uint32_t>* setting_ids, uint32_t unk,
                                      be<uint32_t>* buffer_size_ptr, uint8_t* buffer,
                                      system::XAM_OVERLAPPED* overlapped);
uint32_t XamUserWriteProfileSettings_entry(
    uint32_t title_id, uint32_t user_index, uint32_t setting_count,
    ppc_ptr_t<system::xam::X_USER_PROFILE_SETTING> settings,
    ppc_ptr_t<system::XAM_OVERLAPPED> overlapped);
}


namespace {

struct ProfileReadHeader {
  rex::be<uint32_t> setting_count;
  rex::be<uint32_t> settings_ptr;
};
void StoreBigEndian16(std::array<uint8_t, 0x84>& data, size_t offset, uint16_t value) {
  data[offset] = static_cast<uint8_t>(value >> 8);
  data[offset + 1] = static_cast<uint8_t>(value);
}

void StoreBigEndian32(std::array<uint8_t, 0x84>& data, size_t offset, uint32_t value) {
  data[offset] = static_cast<uint8_t>(value >> 24);
  data[offset + 1] = static_cast<uint8_t>(value >> 16);
  data[offset + 2] = static_cast<uint8_t>(value >> 8);
  data[offset + 3] = static_cast<uint8_t>(value);
}

void InstallTitlelessExecutable(rex::Runtime& runtime) {
  constexpr uint32_t kGuestAddress = 0x80010000;
  std::array<uint8_t, 0x84> elf{};
  elf[0] = 0x7F;
  elf[1] = 'E';
  elf[2] = 'L';
  elf[3] = 'F';
  elf[4] = 1;
  StoreBigEndian16(elf, 16, 2);
  StoreBigEndian16(elf, 18, 20);
  StoreBigEndian32(elf, 20, 1);
  StoreBigEndian32(elf, 24, kGuestAddress);
  StoreBigEndian32(elf, 28, 0x34);
  StoreBigEndian16(elf, 40, 0x34);
  StoreBigEndian16(elf, 42, 0x20);
  StoreBigEndian16(elf, 44, 1);
  StoreBigEndian32(elf, 0x34, 1);
  StoreBigEndian32(elf, 0x38, 0x80);
  StoreBigEndian32(elf, 0x3C, kGuestAddress);
  StoreBigEndian32(elf, 0x40, kGuestAddress);
  StoreBigEndian32(elf, 0x44, 4);
  StoreBigEndian32(elf, 0x48, 4);
  StoreBigEndian32(elf, 0x4C, 5);
  StoreBigEndian32(elf, 0x50, 0x1000);
  StoreBigEndian32(elf, 0x80, 0x4E800020);

  auto module = rex::system::object_ref<rex::system::UserModule>(
      new rex::system::UserModule(runtime.kernel_state()));
  REQUIRE(module->LoadFromMemory(elf.data(), elf.size()) == static_cast<rex::X_STATUS>(0));
  runtime.kernel_state()->SetExecutableModule(std::move(module));
}
struct ProfileReadResult {
  rex::system::xam::X_USER_PROFILE_SETTING setting;
  std::vector<uint8_t> binary;
};

ProfileReadResult ReadProfileSetting(rex::Runtime& runtime, uint32_t setting_id,
                                     bool xuid_mode = false) {
  std::array<rex::be<uint32_t>, 1> setting_ids{setting_id};
  rex::be<uint64_t> xuid = runtime.kernel_state()->user_profile()->xuid();
  auto xuid_count = xuid_mode ? 1u : 0u;
  auto xuids = xuid_mode ? &xuid : nullptr;
  rex::be<uint32_t> buffer_size = 0;
  auto result = rex::kernel::xam::XamUserReadProfileSettingsEx(
      0, 0, xuid_count, xuids, static_cast<uint32_t>(setting_ids.size()), setting_ids.data(), 0,
      &buffer_size, nullptr, nullptr);
  REQUIRE(result == static_cast<rex::X_RESULT>(0x7A));

  auto buffer_address = runtime.memory()->SystemHeapAlloc(buffer_size);
  REQUIRE(buffer_address != 0);
  auto* buffer = runtime.memory()->TranslateVirtual<uint8_t*>(buffer_address);
  REQUIRE(buffer != nullptr);
  result = rex::kernel::xam::XamUserReadProfileSettingsEx(
      0, 0, xuid_count, xuids, static_cast<uint32_t>(setting_ids.size()), setting_ids.data(), 0,
      &buffer_size, buffer, nullptr);
  REQUIRE(result == static_cast<rex::X_RESULT>(0));

  auto* header = reinterpret_cast<ProfileReadHeader*>(buffer);
  REQUIRE(static_cast<uint32_t>(header->setting_count) == setting_ids.size());
  auto* settings =
      runtime.memory()->TranslateVirtual<rex::system::xam::X_USER_PROFILE_SETTING*>(
          static_cast<uint32_t>(header->settings_ptr));
  REQUIRE(settings != nullptr);

  ProfileReadResult read{settings[0], {}};
  if (read.setting.data.type == static_cast<uint8_t>(rex::system::xam::UserProfile::Setting::Type::BINARY) &&
      static_cast<uint32_t>(read.setting.data.binary.size)) {
    auto* data = runtime.memory()->TranslateVirtual<uint8_t*>(
        static_cast<uint32_t>(read.setting.data.binary.ptr));
    REQUIRE(data != nullptr);
    read.binary.assign(data, data + static_cast<uint32_t>(read.setting.data.binary.size));
  }
  runtime.memory()->SystemHeapFree(buffer_address);
  return read;
}


class TempDirectory {
 public:
  TempDirectory() {
    static std::atomic<uint64_t> next_id{0};
    auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    path_ = std::filesystem::temp_directory_path() /
            ("rex_fresh_profile_default_" + std::to_string(suffix) + "_" +
             std::to_string(next_id++));
    std::filesystem::create_directories(path_);
  }

  ~TempDirectory() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }

  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

TEST_CASE("Title profile settings distinguish default, persisted, and invalid data",
          "[system][xam][profile]") {
  TempDirectory temp;
  auto root = temp.path();
  auto user_root = root / "user";
  constexpr uint32_t kDefaultSetting = 0x63E83FFDu;
  constexpr uint32_t kInvalidSetting = 0x63E83FFEu;
  constexpr uint32_t kPersistedSetting = 0x63E83FFFu;

  {
    rex::Runtime runtime(root, user_root);
    rex::RuntimeConfig config;
    config.tool_mode = true;
    REQUIRE(runtime.Setup(std::move(config)) == static_cast<rex::X_STATUS>(0));
    InstallTitlelessExecutable(runtime);

    std::array<rex::be<uint32_t>, 3> setting_ids{kDefaultSetting, kInvalidSetting,
                                                  kPersistedSetting};
    rex::be<uint32_t> buffer_size = 0;
    auto result = rex::kernel::xam::XamUserReadProfileSettingsEx(
        0, 0, 0, nullptr, static_cast<uint32_t>(setting_ids.size()), setting_ids.data(), 0,
        &buffer_size, nullptr, nullptr);
    REQUIRE(result == static_cast<rex::X_RESULT>(0x7A));

    auto buffer_address = runtime.memory()->SystemHeapAlloc(buffer_size);
    REQUIRE(buffer_address != 0);
    auto* buffer = runtime.memory()->TranslateVirtual<uint8_t*>(buffer_address);
    REQUIRE(buffer != nullptr);
    result = rex::kernel::xam::XamUserReadProfileSettingsEx(
        0, 0, 0, nullptr, static_cast<uint32_t>(setting_ids.size()), setting_ids.data(), 0,
        &buffer_size, buffer, nullptr);
    REQUIRE(result == static_cast<rex::X_RESULT>(0));

    auto* header = reinterpret_cast<ProfileReadHeader*>(buffer);
    REQUIRE(static_cast<uint32_t>(header->setting_count) == setting_ids.size());
    auto* settings =
        runtime.memory()->TranslateVirtual<rex::system::xam::X_USER_PROFILE_SETTING*>(
            static_cast<uint32_t>(header->settings_ptr));
    REQUIRE(settings != nullptr);
    for (size_t i = 0; i < setting_ids.size(); ++i) {
      CHECK(static_cast<uint32_t>(settings[i].from) == 1);
      CHECK(settings[i].data.type == 6);
      CHECK(static_cast<uint32_t>(settings[i].data.binary.size) == 0);
      CHECK(static_cast<uint32_t>(settings[i].data.binary.ptr) == 0);
      CHECK(static_cast<uint64_t>(settings[i].xuid) == 0x00000000FFFFFFFFull);
    }
    runtime.memory()->SystemHeapFree(buffer_address);
    auto xuid_setting = ReadProfileSetting(runtime, kDefaultSetting, true);
    CHECK(static_cast<uint64_t>(xuid_setting.setting.xuid) ==
          runtime.kernel_state()->user_profile()->xuid());
  }

  auto profile_dir = user_root / "00000000" / "profile" / "User";
  CHECK_FALSE(std::filesystem::exists(profile_dir));
  const std::vector<uint8_t> expected{0x01, 0x23, 0x45, 0x67};
  {
    rex::Runtime runtime(root, user_root);
    rex::RuntimeConfig config;
    config.tool_mode = true;
    REQUIRE(runtime.Setup(std::move(config)) == static_cast<rex::X_STATUS>(0));
    InstallTitlelessExecutable(runtime);

    auto payload_address = runtime.memory()->SystemHeapAlloc(expected.size());
    auto setting_address =
        runtime.memory()->SystemHeapAlloc(sizeof(rex::system::xam::X_USER_PROFILE_SETTING));
    REQUIRE(payload_address != 0);
    REQUIRE(setting_address != 0);
    auto* payload = runtime.memory()->TranslateVirtual<uint8_t*>(payload_address);
    auto* setting = runtime.memory()->TranslateVirtual<rex::system::xam::X_USER_PROFILE_SETTING*>(
        setting_address);
    REQUIRE(payload != nullptr);
    REQUIRE(setting != nullptr);
    std::memcpy(payload, expected.data(), expected.size());
    *setting = {};
    setting->setting_id = kPersistedSetting;
    setting->data.type = static_cast<uint8_t>(rex::system::xam::UserProfile::Setting::Type::BINARY);
    setting->data.binary.size = static_cast<uint32_t>(expected.size());
    setting->data.binary.ptr = payload_address;
    auto result = rex::kernel::xam::XamUserWriteProfileSettings_entry(
        0, 0, 1, ppc_ptr_t<rex::system::xam::X_USER_PROFILE_SETTING>(setting, setting_address),
        nullptr);
    CHECK(result == static_cast<rex::X_RESULT>(0));
    runtime.memory()->SystemHeapFree(setting_address);
    runtime.memory()->SystemHeapFree(payload_address);
  }

  auto persisted_path = profile_dir / "63E83FFF";
  std::ifstream persisted_file(persisted_path, std::ios::binary);
  REQUIRE(persisted_file);
  CHECK(std::vector<uint8_t>(std::istreambuf_iterator<char>(persisted_file),
                             std::istreambuf_iterator<char>()) == expected);
  REQUIRE(std::filesystem::create_directory(profile_dir / "63E83FFE"));

  {
    rex::Runtime runtime(root, user_root);
    rex::RuntimeConfig config;
    config.tool_mode = true;
    REQUIRE(runtime.Setup(std::move(config)) == static_cast<rex::X_STATUS>(0));
    InstallTitlelessExecutable(runtime);

    auto persisted = ReadProfileSetting(runtime, kPersistedSetting);
    CHECK(static_cast<uint32_t>(persisted.setting.from) == 2);
    CHECK(persisted.setting.data.type == 6);
    CHECK(static_cast<uint32_t>(persisted.setting.data.binary.size) == expected.size());
    CHECK(persisted.binary == expected);

    auto invalid = ReadProfileSetting(runtime, kInvalidSetting);
    CHECK(static_cast<uint32_t>(invalid.setting.from) == 0);
    CHECK(invalid.setting.data.type == 0);
    CHECK(static_cast<uint32_t>(invalid.setting.data.binary.size) == 0);
    CHECK(static_cast<uint32_t>(invalid.setting.data.binary.ptr) == 0);
    REQUIRE(std::filesystem::remove(profile_dir / "63E83FFE"));
    auto retried = ReadProfileSetting(runtime, kInvalidSetting);
    CHECK(static_cast<uint32_t>(retried.setting.from) == 1);
    CHECK(retried.setting.data.type == 6);
    CHECK(static_cast<uint32_t>(retried.setting.data.binary.size) == 0);
    CHECK(static_cast<uint32_t>(retried.setting.data.binary.ptr) == 0);
  }
}

TEST_CASE("Stats enumerator creation returns an empty enumerator handle",
          "[system][xam][profile]") {
  TempDirectory temp;
  rex::Runtime runtime(temp.path(), temp.path() / "user");
  rex::RuntimeConfig config;
  config.tool_mode = true;
  REQUIRE(runtime.Setup(std::move(config)) == static_cast<rex::X_STATUS>(0));
  InstallTitlelessExecutable(runtime);

  auto* memory = runtime.memory();
  auto stats_address = memory->SystemHeapAlloc(0x100);
  auto out_address = memory->SystemHeapAlloc(8);
  REQUIRE(stats_address != 0);
  REQUIRE(out_address != 0);
  auto* out = memory->TranslateVirtual<rex::be<uint32_t>*>(out_address);

  auto call = [&](uint32_t user_index, uint32_t count, uint32_t flags, uint32_t size) {
    out[0] = 0xDEADBEEF;
    out[1] = 0xDEADBEEF;
    PPCContext ctx{};
    ctx.r3.u64 = 0x584109E2;
    ctx.r4.u64 = user_index;
    ctx.r5.u64 = count;
    ctx.r6.u64 = flags;
    ctx.r7.u64 = size;
    ctx.r8.u64 = stats_address;
    ctx.r9.u64 = out_address;
    ctx.r10.u64 = out_address + 4;
    __imp__XamUserCreateStatsEnumerator(ctx, memory->virtual_membase());
    return static_cast<uint32_t>(ctx.r3.u64);
  };

  REQUIRE(call(0, 1, 1, 0x40) == 0);
  CHECK(static_cast<uint32_t>(out[0]) == 0);
  auto handle = static_cast<uint32_t>(out[1]);
  auto enumerator =
      runtime.kernel_state()->object_table()->LookupObject<rex::system::XEnumerator>(handle);
  REQUIRE(enumerator);
  uint32_t written = 0;
  CHECK(enumerator->WriteItems(0, nullptr, &written) == 0x12u);  // X_ERROR_NO_MORE_FILES

  CHECK(call(4, 1, 1, 0x40) == 0x57u);  // X_ERROR_INVALID_PARAMETER
  CHECK(call(0, 0, 1, 0x40) == 0x57u);
  CHECK(call(0, 1, 0, 0x40) == 0x57u);
  CHECK(call(0, 1, 0x65, 0x40) == 0x57u);
  CHECK(call(0, 1, 1, 0) == 0x57u);
  CHECK(static_cast<uint32_t>(out[1]) == 0xDEADBEEF);

  memory->SystemHeapFree(out_address);
  memory->SystemHeapFree(stats_address);
}

TEST_CASE("Overlapped profile writes persist buffer contents at completion",
          "[system][xam][profile]") {
  TempDirectory temp;
  auto user_root = temp.path() / "user";
  constexpr uint32_t kSetting = 0x63E83FFFu;
  const std::vector<uint8_t> final_bytes{0x01, 0x00, 0x01, 0x00};
  {
    rex::Runtime runtime(temp.path(), user_root);
    rex::RuntimeConfig config;
    config.tool_mode = true;
    REQUIRE(runtime.Setup(std::move(config)) == static_cast<rex::X_STATUS>(0));
    InstallTitlelessExecutable(runtime);
    auto* memory = runtime.memory();

    auto payload_address = memory->SystemHeapAlloc(4);
    auto setting_address = memory->SystemHeapAlloc(sizeof(rex::system::xam::X_USER_PROFILE_SETTING));
    auto overlapped_address = memory->SystemHeapAlloc(sizeof(rex::system::XAM_OVERLAPPED));
    REQUIRE(payload_address != 0);
    REQUIRE(setting_address != 0);
    REQUIRE(overlapped_address != 0);
    auto* payload = memory->TranslateVirtual<uint8_t*>(payload_address);
    auto* setting =
        memory->TranslateVirtual<rex::system::xam::X_USER_PROFILE_SETTING*>(setting_address);
    auto* overlapped = memory->TranslateVirtual<rex::system::XAM_OVERLAPPED*>(overlapped_address);
    std::memset(payload, 0, 4);
    *setting = {};
    std::memset(overlapped, 0, sizeof(*overlapped));
    setting->from = 2;
    setting->setting_id = kSetting;
    setting->data.type = static_cast<uint8_t>(rex::system::xam::UserProfile::Setting::Type::BINARY);
    setting->data.binary.size = 4;
    setting->data.binary.ptr = payload_address;

    // The game issues the write, then fills the buffer before the request completes.
    uint32_t result = 0;
    auto thread = rex::system::object_ref<rex::system::XHostThread>(new rex::system::XHostThread(
        runtime.kernel_state(), 128 * 1024, 0, [&]() {
          result = rex::kernel::xam::XamUserWriteProfileSettings_entry(
              0, 0, 1,
              ppc_ptr_t<rex::system::xam::X_USER_PROFILE_SETTING>(setting, setting_address),
              ppc_ptr_t<rex::system::XAM_OVERLAPPED>(overlapped, overlapped_address));
          std::memcpy(payload, final_bytes.data(), final_bytes.size());
          return 0;
        }));
    REQUIRE(thread->Create() == static_cast<rex::X_STATUS>(0));
    thread->Wait(0, 0, 0, nullptr);
    REQUIRE(result == 0x3E5u);  // X_ERROR_IO_PENDING

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (static_cast<uint32_t>(overlapped->result) == 0x3E5u &&
           std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    REQUIRE(static_cast<uint32_t>(overlapped->result) == 0);
  }

  std::ifstream persisted(user_root / "00000000" / "profile" / "User" / "63E83FFF",
                          std::ios::binary);
  REQUIRE(persisted);
  CHECK(std::vector<uint8_t>(std::istreambuf_iterator<char>(persisted),
                             std::istreambuf_iterator<char>()) == final_bytes);
}

TEST_CASE("Local players are signed in from startup for local multiplayer",
          "[system][xam][profile]") {
  TempDirectory temp;
  REQUIRE(rex::cvar::SetFlagByName("local_players", "2"));
  rex::Runtime runtime(temp.path(), temp.path() / "user");
  rex::RuntimeConfig config;
  config.tool_mode = true;
  REQUIRE(runtime.Setup(std::move(config)) == static_cast<rex::X_STATUS>(0));
  InstallTitlelessExecutable(runtime);

  auto* memory = runtime.memory();
  auto out_address = memory->SystemHeapAlloc(64);
  REQUIRE(out_address != 0);
  auto* base = memory->virtual_membase();
  auto signin_state = [&](uint32_t user) {
    PPCContext ctx{};
    ctx.r3.u64 = user;
    __imp__XamUserGetSigninState(ctx, base);
    return static_cast<uint32_t>(ctx.r3.u64);
  };
  auto xuid = [&](uint32_t user) {
    PPCContext ctx{};
    ctx.r3.u64 = user;
    ctx.r4.u64 = 1;
    ctx.r5.u64 = out_address;
    __imp__XamUserGetXUID(ctx, base);
    return std::pair<uint32_t, uint64_t>(
        static_cast<uint32_t>(ctx.r3.u64),
        static_cast<uint64_t>(*memory->TranslateVirtual<rex::be<uint64_t>*>(out_address)));
  };

  // No controllers at all: the profiles exist anyway, fixed for the whole session.
  CHECK(signin_state(0) == 1);
  CHECK(signin_state(1) == 1);
  CHECK(signin_state(2) == 0);
  auto [result1, xuid1] = xuid(1);
  CHECK(result1 == 0);
  CHECK(xuid1 != 0);
  CHECK(xuid1 != xuid(0).second);
  CHECK(xuid(2).first != 0);
  PPCContext ctx{};
  ctx.r3.u64 = 1;
  ctx.r5.u64 = out_address;
  __imp__XamUserGetSigninInfo(ctx, base);
  CHECK(static_cast<uint32_t>(ctx.r3.u64) == 0);
  CHECK(std::string(memory->TranslateVirtual<const char*>(out_address + 24)) == "Player 2");

  // Player 2 reads and writes its own title data, in its own folder.
  std::array<rex::be<uint32_t>, 1> ids{0x63E83FFFu};
  rex::be<uint32_t> size = 0;
  CHECK(rex::kernel::xam::XamUserReadProfileSettingsEx(0, 1, 0, nullptr, 1, ids.data(), 0, &size,
                                                       nullptr, nullptr) == 0x7Au);
  auto buffer_address = memory->SystemHeapAlloc(size);
  auto* buffer = memory->TranslateVirtual<uint8_t*>(buffer_address);
  CHECK(rex::kernel::xam::XamUserReadProfileSettingsEx(0, 1, 0, nullptr, 1, ids.data(), 0, &size,
                                                       buffer, nullptr) == 0u);
  memory->SystemHeapFree(buffer_address);
  auto payload_address = memory->SystemHeapAlloc(4);
  auto setting_address =
      memory->SystemHeapAlloc(sizeof(rex::system::xam::X_USER_PROFILE_SETTING));
  auto* payload = memory->TranslateVirtual<uint8_t*>(payload_address);
  auto* setting =
      memory->TranslateVirtual<rex::system::xam::X_USER_PROFILE_SETTING*>(setting_address);
  std::memcpy(payload, "\x02\x00\x02\x00", 4);
  *setting = {};
  setting->setting_id = 0x63E83FFFu;
  setting->data.type = static_cast<uint8_t>(rex::system::xam::UserProfile::Setting::Type::BINARY);
  setting->data.binary.size = 4;
  setting->data.binary.ptr = payload_address;
  CHECK(rex::kernel::xam::XamUserWriteProfileSettings_entry(
            0, 1, 1, ppc_ptr_t<rex::system::xam::X_USER_PROFILE_SETTING>(setting, setting_address),
            nullptr) == 0u);
  memory->SystemHeapFree(setting_address);
  memory->SystemHeapFree(payload_address);
  auto profile_root = temp.path() / "user" / "00000000" / "profile";
  CHECK(std::filesystem::exists(profile_root / "Player 2" / "63E83FFF"));
  CHECK_FALSE(std::filesystem::exists(profile_root / "User" / "63E83FFF"));

  REQUIRE(rex::cvar::SetFlagByName("local_players", "1"));  // default: single player
  CHECK(signin_state(1) == 0);
  memory->SystemHeapFree(out_address);
}
}  // namespace
