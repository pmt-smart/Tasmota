/*
  xdrv_99_rtc_retain.ino - keep the clock's time across a restart that is not a power cycle

  Copyright (C) 2026  HouseWeave

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
#ifdef USE_RTC_RETAIN
/*********************************************************************************************\
 * The clock's time, kept across a restart.
 *
 * Every boot starts with the clock at 0 (RtcInit), and only a time source sets it
 * again. On a device with no network there is none, so every restart (an OTA,
 * Restart 1, a crash, a watchdog) loses a time that was set by hand with `Time`.
 *
 * The ESP32's RTC slow memory and its RTC counter both survive a restart that is
 * not a power cycle. Every second, with the clock set, this keeps the UTC time,
 * the RTC counter at that second, and whether the time is the user's (`Time
 * <epoch>`, which keeps the NTP from changing it). At the next boot, when the
 * reset was a software one, a panic, a watchdog's or the wake from deep sleep,
 * and the record is whole, the clock comes back as the time kept plus what the
 * counter ran since. The counter runs on an imprecise clock, but only for the
 * seconds of the restart: the time comes back within about a second. A time
 * that was the user's is the user's again, so the NTP stays off it, and no
 * Time#Set is raised, since nothing set the time.
 *
 * Commands:
 *   RtcRetain         - whether this boot's time was kept across the restart,
 *                       and the seconds the restart took
\*********************************************************************************************/

#define XDRV_99                         99

#include "esp_rtc_time.h"

#ifndef RTC_RETAIN_MAX_GAP_S
#define RTC_RETAIN_MAX_GAP_S            3600     // a restart said to take longer than this is not believed
#endif
#define RTC_RETAIN_MAGIC                0x52544352  // "RTCR"

struct RTC_RETAIN_RECORD {
  uint32_t magic;
  uint32_t utc;                          // the UTC time at the second kept
  uint64_t counter_us;                   // the RTC counter at that second
  uint32_t user;                         // the time was the user's (Rtc.user_time_entry)
  uint32_t check;                        // the fields above, folded together: a record half written is not whole
};
static RTC_NOINIT_ATTR RTC_RETAIN_RECORD RtcRetainRecord;

struct RTC_RETAIN {
  bool restored;                         // this boot's time is the one kept
  uint32_t gap;                          // the seconds the restart took, as the counter ran them
} RtcRetain;

// The fields folded together. Not a struct argument: the Arduino build declares every function at the top of the
// sketch, before the struct is
static uint32_t RtcRetainCheck(uint32_t magic, uint32_t utc, uint64_t counter_us, uint32_t user) {
  return magic ^ utc ^ (uint32_t)counter_us ^ (uint32_t)(counter_us >> 32) ^ user ^ 0xA5A5A5A5;
}

// At the boot, after RtcInit set the clock to 0
static void RtcRetainRestore(void) {
  RTC_RETAIN_RECORD r = RtcRetainRecord;
  RtcRetainRecord.magic = 0;             // a record is used once
  esp_reset_reason_t reason = esp_reset_reason();
  bool kept = (ESP_RST_SW == reason) || (ESP_RST_PANIC == reason) || (ESP_RST_INT_WDT == reason) ||
              (ESP_RST_TASK_WDT == reason) || (ESP_RST_WDT == reason) || (ESP_RST_DEEPSLEEP == reason);
  if (!kept || (RTC_RETAIN_MAGIC != r.magic) || (r.check != RtcRetainCheck(r.magic, r.utc, r.counter_us, r.user)) || (r.utc < START_VALID_TIME)) { return; }
  uint64_t now_us = esp_rtc_get_time_us();
  // a counter behind the one kept started again: the RTC itself was reset
  if (now_us < r.counter_us) { return; }
  uint64_t gap = (now_us - r.counter_us) / 1000000ULL;
  if (gap > RTC_RETAIN_MAX_GAP_S) { return; }
  Rtc.utc_time = r.utc + (uint32_t)gap;
  Rtc.user_time_entry = (r.user != 0);
  RtcRetain.restored = true;
  RtcRetain.gap = (uint32_t)gap;
  AddLog(LOG_LEVEL_INFO, PSTR("RTC: Time kept across the restart, which took %d s"), RtcRetain.gap);
}

static void RtcRetainSave(void) {
  if (Rtc.utc_time < START_VALID_TIME) { return; }
  RtcRetainRecord.magic = RTC_RETAIN_MAGIC;
  RtcRetainRecord.utc = Rtc.utc_time;
  RtcRetainRecord.counter_us = esp_rtc_get_time_us();
  RtcRetainRecord.user = Rtc.user_time_entry ? 1 : 0;
  RtcRetainRecord.check = RtcRetainCheck(RtcRetainRecord.magic, RtcRetainRecord.utc, RtcRetainRecord.counter_us, RtcRetainRecord.user);
}

/*********************************************************************************************\
 * Commands
\*********************************************************************************************/

void CmndRtcRetain(void) {
  Response_P(PSTR("{\"%s\":{\"Restored\":%d,\"Gap\":%d}}"), XdrvMailbox.command, RtcRetain.restored, RtcRetain.gap);
}

// Leading "|" marks a flat command list without a shared prefix.
const char kRtcRetainCommands[] PROGMEM = "|" "RtcRetain";
void (* const kRtcRetainCommand[])(void) PROGMEM = { &CmndRtcRetain };

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv99(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_PRE_INIT:
      RtcRetainRestore();
      break;
    case FUNC_EVERY_SECOND:
      RtcRetainSave();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kRtcRetainCommands, kRtcRetainCommand);
      break;
  }
  return result;
}

#endif  // USE_RTC_RETAIN
#endif  // ESP32
