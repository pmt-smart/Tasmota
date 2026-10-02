/*
  xdrv_95_boot_rescue.ino - open the WiFi Manager after a few short boots in a row

  Copyright (C) 2026  Casa Inteligente

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef ESP32
#ifdef USE_BOOT_RESCUE
/*********************************************************************************************\
 * A way back into a device that has no other: its reset button, or its power.
 *
 * Every boot that ends before BOOT_RESCUE_WINDOW_S seconds counts as short, the
 * way Tasmota's quick power cycle detection counts them. On the
 * BOOT_RESCUE_BOOTS-th short boot in a row the WiFi Manager opens, as
 * `WifiConfig 2` opens it, for its own WIFI_CONFIG_SEC, instead of the settings
 * being erased. It opens BOOT_RESCUE_OPEN_S seconds into that boot, once a
 * script that turns the WiFi off at boot has done so, and turns the WiFi on
 * first, as `Wifi 1` does. Its time runs on a device with no network saved
 * too, as on one with a network: each page served gives it again, and the
 * device restarts when it runs out.
 *
 * For a device whose button no longer reaches the WiFi Manager (a button driver
 * that takes it, or SetOption1), whose screen does not work, or whose network
 * was lost: pressing the reset button three times, each within a few seconds of
 * the boot, is the gesture. A device that keeps crashing at boot opens it too.
 * Tasmota's own detection (SetOption65 0) erases the settings after seven: with
 * both on, the rescue comes first.
 *
 * The count lives in its own NVS namespace, and is written twice a boot: once
 * as the boot starts, and once as it becomes long.
 *
 * Commands:
 *   BootRescue        - the short boots counted, and whether the rescue is due
\*********************************************************************************************/

#define XDRV_95                         95

#ifndef BOOT_RESCUE_BOOTS
#define BOOT_RESCUE_BOOTS               3        // short boots in a row that open the WiFi Manager
#endif
#ifndef BOOT_RESCUE_WINDOW_S
#define BOOT_RESCUE_WINDOW_S            10       // a boot that lasts this long is not short
#endif
#ifndef BOOT_RESCUE_OPEN_S
#define BOOT_RESCUE_OPEN_S              20       // when the WiFi Manager opens, in the boot that asks for it
#endif

#define BOOT_RESCUE_NVS_NAMESPACE       "boot_rescue"
#define BOOT_RESCUE_VERSION             1

struct BOOT_RESCUE_SETTINGS {
  uint8_t version;
  uint8_t short_boots;                   // boots in a row that ended before the window closed
} BootRescueSettings = { BOOT_RESCUE_VERSION, 0 };

struct BOOT_RESCUE {
  bool due;                              // this boot opens the WiFi Manager
  bool settled;                          // this boot is long: the count is back to none
} BootRescue;

static void BootRescueSave(void) {
  NvmSave(BOOT_RESCUE_NVS_NAMESPACE, "settings", &BootRescueSettings, sizeof(BootRescueSettings));
}

// As the boot starts: one more short boot, until it proves long
static void BootRescueStart(void) {
  // NvmLoad() returns true as soon as the namespace opens, even with no blob to
  // read, and leaves the buffer as it was: version 0 is never ours
  BOOT_RESCUE_SETTINGS loaded = { 0, 0 };
  if (NvmLoad(BOOT_RESCUE_NVS_NAMESPACE, "settings", &loaded, sizeof(loaded)) &&
      (BOOT_RESCUE_VERSION == loaded.version)) {
    BootRescueSettings = loaded;
  }
  if (BootRescueSettings.short_boots < 255) { BootRescueSettings.short_boots++; }
  if (BootRescueSettings.short_boots >= BOOT_RESCUE_BOOTS) {
    BootRescue.due = true;
    BootRescueSettings.short_boots = 0;    // the next count starts from none, whatever this boot does
  }
  BootRescueSave();
  AddLog(LOG_LEVEL_INFO, PSTR("RSC: Boot %d of %d short ones in a row"),
    BootRescue.due ? BOOT_RESCUE_BOOTS : BootRescueSettings.short_boots, BOOT_RESCUE_BOOTS);
}

static void BootRescueEverySecond(void) {
  if (!BootRescue.settled && (TasmotaGlobal.uptime >= BOOT_RESCUE_WINDOW_S)) {
    BootRescue.settled = true;
    if (BootRescueSettings.short_boots) {
      BootRescueSettings.short_boots = 0;
      BootRescueSave();
    }
  }
  if (BootRescue.due && (TasmotaGlobal.uptime >= BOOT_RESCUE_OPEN_S)) {
    BootRescue.due = false;
    AddLog(LOG_LEVEL_INFO, PSTR("RSC: %d short boots in a row, the WiFi Manager opens for %d s"), BOOT_RESCUE_BOOTS, WIFI_CONFIG_SEC);
    Settings->flag4.network_wifi = 1;    // as Wifi 1: a script may have turned the WiFi off at boot
    WifiConfig(WIFI_MANAGER);
#ifdef USE_WEBSERVER
    // A device with no network saved is in its initial configuration, where the
    // web server holds Wifi.config_counter up and the WiFi Manager stays open with
    // no time limit, its administration with it. Opened as a rescue, it closes as
    // on a device with a network: in WIFI_CONFIG_SEC, each page giving that time
    // again, and with a restart
    Web.initial_config = false;
#endif  // USE_WEBSERVER
  }
}

/*********************************************************************************************\
 * Commands
\*********************************************************************************************/

void CmndBootRescue(void) {
  Response_P(PSTR("{\"%s\":{\"ShortBoots\":%d,\"Of\":%d,\"Due\":%d}}"),
    XdrvMailbox.command, BootRescueSettings.short_boots, BOOT_RESCUE_BOOTS, BootRescue.due);
}

// Leading "|" marks a flat command list without a shared prefix.
const char kBootRescueCommands[] PROGMEM = "|" "BootRescue";
void (* const kBootRescueCommand[])(void) PROGMEM = { &CmndBootRescue };

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv95(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_PRE_INIT:
      BootRescueStart();
      break;
    case FUNC_EVERY_SECOND:
      BootRescueEverySecond();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kBootRescueCommands, kBootRescueCommand);
      break;
  }
  return result;
}

#endif  // USE_BOOT_RESCUE
#endif  // ESP32
