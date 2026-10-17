/*
  xdrv_98_2_espnow_mesh_probe.ino - ESP-NOW off-channel probe: frames sent and heard on a channel other than the station's

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

#ifdef USE_ESPNOW_MESH
#ifdef USE_ESPNOW_MESH_PROBE
/*********************************************************************************************\
 * A bench tool for ESP-NOW on more than one channel. A station associated with an access point
 * stays on the access point's channel, and ESP-NOW with it. ESP-IDF 5.5 can send one ESP-NOW frame
 * on another channel and come back (esp_now_switch_channel_tx), and stay on another channel for a
 * while to hear what is sent there (esp_now_remain_on_channel). This driver measures whether both
 * work with the station associated, how long the radio is away, and what the station and the frames
 * sent on its own channel lose meanwhile.
 *
 * Probe frames begin with a byte no other ESP-NOW protocol on the radio uses (the mesh's is 0x41, the
 * direct link's types end at 0x23), and the mesh's receive callback hands them here before it looks
 * at a frame: the probe rides on the mesh's radio, which has to be running. A device answers every
 * probe sent to it alone with an echo, on the channel the sender says it lives on, and the sender
 * counts the echoes and their round trip. A send takes the mesh's radio lock, so that no frame of the
 * mesh goes out while the radio is away.
 *
 * Commands:
 *   EspNowProbe                - the channel, the counters, and the result of the last run
 *   EspNowProbe 0              - the counters cleared
 *   EspNowProbeSend <mac>,<channel>[,<count>[,<interval ms>[,<wait ms>[,<size>]]]]
 *                                <count> probes (10) to <mac>, one every <interval> (100 ms), on <channel> (0: the radio's). On a channel
 *                                that is not the radio's, by esp_now_switch_channel_tx, which keeps the radio there <wait> ms (10). <size>
 *                                is the frame's length, 18 to 250 (18). ff:ff:ff:ff:ff:ff broadcasts: no acknowledgement, no echo
 *   EspNowProbeListen <channel>,<ms>[,<count>[,<interval ms>]]
 *                                the radio stays <ms> on <channel> (esp_now_remain_on_channel), and counts the probe frames heard there.
 *                                With <count>, it also sends that many broadcast beacons while there, one every <interval> (50 ms), by
 *                                esp_now_send: whether a frame can be sent during a remain-on-channel, and on which channel it goes out
 *   EspNowProbeNap <channel>,<beacons>,<home ms>[,<seconds>[,<tx>[,<beacon TU>[,<ps>]]]]
 *                                a station that lives on <channel> and naps on its access point: every <beacons> beacon intervals, the
 *                                radio comes home for <home ms> around the beacon (the window is anchored on the TBTT, from the station's
 *                                TSF) and stays on <channel> the rest of the time (esp_now_remain_on_channel), for <seconds> (60; up to
 *                                3600). <tx> 1 sends a broadcast beacon on <channel> each time it gets there. <beacon TU> is the access
 *                                point's beacon interval (100). The multi-channel concurrency of a Wi-Fi driver, in probe form: what the
 *                                station keeps (its beacons, its link, a ping from the LAN) and what it hears on <channel> meanwhile.
 *                                <ps> 1 tells the access point before each stay that the station dozes (a null frame with the power
 *                                management bit, by esp_wifi_80211_tx), and that it is awake once back (the bit clear): the access point
 *                                keeps the station's frames while it is away, as it does for a station in power save, and sends them then
 *                                EspNowProbeNap 0 ends it after the current period
 *   EspNowProbeAway <channel>,<seconds>[,<beacon ms>]
 *                                stands in for a device with no network: the WiFi pauses, the radio goes to <channel> for <seconds>, with
 *                                a broadcast beacon every <beacon ms> (0: none) and an echo for each probe, and the WiFi comes back as it
 *                                was. The web server is down meanwhile; the summary comes after, in the log and in EspNowProbe
 *
 * EspNowProbe also counts, since the last EspNowProbe 0: the 100 ms ticks the radio was on another channel than the mesh's setting
 * (a station with a network it cannot reach scans for it, and leaves the channel), and the Wi-Fi events of a scan done, a beacon
 * timeout and a disconnection.
 *
 * Results go to the log and to the rule engine:
 *   {"EspNowProbe":{"Kind":"Send",...}} at the end of a run, {"EspNowProbeAway":{"State":"Back",...}} at the end of an away
\*********************************************************************************************/

#define XDRV_101                       101

#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_timer.h>

#define ESPNOW_PROBE_MAGIC             0x50
#define ESPNOW_PROBE_PROBE             1       // asks the device it is sent to for an echo
#define ESPNOW_PROBE_ECHO              2
#define ESPNOW_PROBE_BEACON            3       // a device away, broadcasting on its channel
#define ESPNOW_PROBE_JOBS              8
#define ESPNOW_PROBE_TASK_STACK        4096
#define ESPNOW_PROBE_TASK_PRIORITY     5
#define ESPNOW_PROBE_MAX_FRAME         250     // what an ESP-NOW v1.0 device takes
#define ESPNOW_PROBE_ECHO_WAIT_MS      300     // the echoes of a run's last probes are counted until then
#define ESPNOW_PROBE_AWAY_MAX_S        600
#define ESPNOW_PROBE_NAP_MAX_S         3600
#define ESPNOW_PROBE_NAP_GUARD_US      2000    // the radio is meant to be home this long before the beacon
#define ESPNOW_PROBE_NAP_LEAVE_US      8000    // what a remain-on-channel takes to get to the channel, by the first run of the probe (the send
                                               // callback of a frame sent away came 4 to 9 ms after the call): the request is made this much
                                               // shorter than the time left to the return
#define ESPNOW_PROBE_NAP_MIN_WAIT_MS   5       // a remain-on-channel shorter than this is skipped
#define ESPNOW_PROBE_NAP_PS_WAIT_MS    5       // the radio's word on a null frame is waited for this long
#define ESPNOW_PROBE_ROC_TX_DELAY_MS   12      // a frame sent during a remain-on-channel waits this long after the request, for the radio to get there

typedef struct __attribute__((packed)) {
  uint8_t magic;
  uint8_t kind;
  uint8_t home;            // the sender's channel, where an echo goes
  uint8_t sent_on;         // the channel the sender sent it on
  uint32_t seq;
  uint32_t sent_us;        // the sender's clock, low 32 bits, which the echo carries back
  uint32_t heard;          // echo: the probes the device that echoes has heard
  int8_t rssi;             // echo: the probe's signal
  uint8_t rx_channel;      // echo: the channel the probe was heard on
} EspNowProbeFrame_t;

enum EspNowProbeJobs { ESPNOW_PROBE_JOB_ECHO = 1, ESPNOW_PROBE_JOB_SEND, ESPNOW_PROBE_JOB_LISTEN, ESPNOW_PROBE_JOB_WAKE, ESPNOW_PROBE_JOB_NAP };

typedef struct {
  uint8_t type;
  uint8_t mac[6];
  uint8_t channel;
  uint16_t wait_ms;
  uint16_t size;
  uint32_t count;              // send: the probes; listen: the beacons sent during it; nap: the beacon intervals of a period
  uint32_t interval_ms;        // send: between probes; listen: the stay, and between its beacons in tx_interval_ms; nap: the time home
  uint16_t tx_interval_ms;
  uint16_t seconds;            // nap: how long
  uint16_t beacon_tu;          // nap: the access point's beacon interval
  uint8_t tx;                  // nap: a beacon sent on the channel each period
  uint8_t ps;                  // nap: the access point told before each stay that the station dozes, and once back that it is awake
  EspNowProbeFrame_t frame;    // echo: the probe heard
} EspNowProbeJob_t;

// What the frames sent during a remain-on-channel did
typedef struct {
  uint32_t sent;
  uint32_t api_err;
  int32_t last_err;
  uint32_t acked;
  uint32_t nacked;
  uint32_t no_word;
  uint8_t channel;             // what esp_wifi_get_channel said while there, the last time
} EspNowProbeRocTx_t;

// What the null frames of a nap did
typedef struct {
  uint32_t sent;
  uint32_t api_err;
  int32_t last_err;
  uint32_t acked;
  uint32_t failed;
  uint32_t no_word;
} EspNowProbeNull_t;

// What one send did, as the task saw it
typedef struct {
  esp_err_t err;
  bool off;                    // to another channel than the radio's
  bool word;                   // the radio's send callback came
  bool ok;                     // and said acknowledged (sent, for a broadcast)
  bool back;                   // the radio said it was back on its channel (WIFI_EVENT_ACTION_TX_STATUS)
  uint8_t back_status;
  uint32_t call_us;            // how long the call took
  uint32_t word_us;            // from the call to the send callback
  uint32_t back_us;            // from the call to the radio back
} EspNowProbeTx_t;

typedef struct {
  uint32_t n;
  uint32_t min;
  uint32_t max;
  uint64_t sum;
} EspNowProbeSpan_t;

// The last run, a send or a listen: written by the task, and the echoes by the WiFi task, read by the main loop once done
typedef struct {
  uint8_t kind;                // ESPNOW_PROBE_JOB_SEND or _LISTEN, 0 none yet
  uint8_t mac[6];
  uint8_t channel;
  uint8_t home;
  bool associated;
  uint32_t count;
  uint32_t interval_ms;
  uint16_t wait_ms;
  uint16_t size;
  uint32_t sent;
  uint32_t api_err;
  int32_t last_err;
  uint32_t acked;
  uint32_t nacked;
  uint32_t no_word;
  uint32_t back;
  uint32_t cancelled;
  uint32_t no_back;
  uint32_t call_us_max;
  EspNowProbeSpan_t word;
  EspNowProbeSpan_t away;
  uint32_t first_seq;
  volatile uint32_t last_seq;
  volatile uint32_t echoes;
  EspNowProbeSpan_t rtt;       // touched by the WiFi task only
  int32_t roc_err;
  bool roc_done;
  uint32_t roc_us;
  uint32_t heard;
  EspNowProbeRocTx_t tx;       // listen and nap: the frames sent while on the channel
  // nap
  uint16_t home_ms;
  uint16_t beacon_tu;
  uint16_t seconds;
  uint32_t periods;            // the periods the radio went to the channel
  uint32_t skipped;            // the periods it did not: too little time left
  uint32_t roc_refused;        // the requests esp_now_remain_on_channel refused
  uint32_t roc_cancelled;
  uint32_t roc_no_back;
  uint32_t late;               // the returns after the beacon's time
  EspNowProbeSpan_t late_us;   // how long after the planned return the radio was back
  uint32_t tsf_lost;           // the periods the station's TSF could not be read: not associated
  bool ps;                     // the null frames were asked for, and the access point was known
  EspNowProbeNull_t null;
  uint32_t ms;
  volatile bool done;
  bool reported;
} EspNowProbeRun_t;

struct {
  TaskHandle_t task = nullptr;
  QueueHandle_t jobs = nullptr;
  SemaphoreHandle_t word = nullptr;          // the radio's word on a send
  SemaphoreHandle_t back = nullptr;          // the radio back on its channel, after a send away or a listen
  SemaphoreHandle_t null_word = nullptr;     // the radio's word on a null frame
  volatile bool null_ok = false;
  bool events = false;                       // the WiFi event handlers are registered
  volatile bool awaiting = false;
  uint8_t send_to[6];
  volatile bool word_ok = false;
  volatile int64_t word_at = 0;
  volatile int64_t back_at = 0;
  volatile uint8_t back_status = 0;
  volatile bool busy = false;                // a send or a listen is under way
  volatile uint32_t seq = 0;
  volatile uint8_t home = 0;                 // the radio's channel, as the main loop last read it
  volatile uint32_t heard_probe = 0;
  volatile uint32_t heard_echo = 0;
  volatile uint32_t heard_beacon = 0;
  volatile uint32_t heard_off = 0;           // heard on another channel than the radio's
  volatile int8_t last_rssi = 0;
  volatile uint8_t last_channel = 0;
  volatile uint32_t echo_sent = 0;
  volatile uint32_t echo_failed = 0;
  volatile int32_t echo_err = 0;            // the last echo that failed: the call's error, or -1 when the radio said it was not acknowledged
  volatile uint32_t beacon_sent = 0;
  volatile uint32_t beacon_failed = 0;
  volatile uint32_t queue_full = 0;
  volatile bool listening = false;
  volatile uint8_t listen_channel = 0;
  volatile uint32_t listen_heard = 0;
  volatile bool stop = false;                // EspNowProbeNap 0
  // Since the last EspNowProbe 0: the Wi-Fi events counted, and the ticks the radio was off the mesh's channel
  volatile uint32_t scan_done = 0;
  volatile uint32_t beacon_timeout = 0;
  volatile uint32_t disconnected = 0;
  uint32_t ticks = 0;
  uint32_t off_ticks = 0;
  // EspNowProbeAway, on the main loop; away_on once the radio is on the channel, which the task beacons on
  bool away = false;
  bool away_paused = false;                  // the WiFi is paused, a tick after the command, whose answer goes out first
  volatile bool away_on = false;
  uint8_t away_channel = 0;
  uint16_t beacon_ms = 0;
  uint32_t away_until = 0;
  uint32_t away_since = 0;
  uint32_t away_probes = 0;
  uint32_t away_echoes = 0;
  uint32_t away_beacons = 0;
  EspNowProbeRun_t run;
} EspNowProbe;

static const uint8_t EspNowProbeBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/*********************************************************************************************\
 * From the WiFi task and the event loop: they only count, record and queue
\*********************************************************************************************/

static void EspNowProbeSpanAdd(EspNowProbeSpan_t* span, uint32_t value);
static void EspNowProbeSpanAdd(EspNowProbeSpan_t* span, uint32_t value) {
  if (!span->n || (value < span->min)) { span->min = value; }
  if (value > span->max) { span->max = value; }
  span->sum += value;
  span->n++;
}

// The mesh's receive callback, first: true when the frame is a probe's
bool EspNowProbeHears(const esp_now_recv_info_t* info, const uint8_t* data, int len);
bool EspNowProbeHears(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
  if ((len < 1) || (ESPNOW_PROBE_MAGIC != data[0])) { return false; }
  if (len < (int)sizeof(EspNowProbeFrame_t)) { return true; }
  EspNowProbeFrame_t frame;
  memcpy(&frame, data, sizeof(frame));
  uint8_t channel = info->rx_ctrl->channel;
  int8_t rssi = info->rx_ctrl->rssi;
  EspNowProbe.last_rssi = rssi;
  EspNowProbe.last_channel = channel;
  if (channel != EspNowProbe.home) { EspNowProbe.heard_off++; }
  if (EspNowProbe.listening && (channel == EspNowProbe.listen_channel)) { EspNowProbe.listen_heard++; }
  switch (frame.kind) {
    case ESPNOW_PROBE_PROBE: {
      EspNowProbe.heard_probe++;
      if (!memcmp(info->des_addr, EspNowProbeBroadcast, 6) || !EspNowProbe.jobs) { break; }
      EspNowProbeJob_t job;
      memset(&job, 0, sizeof(job));
      job.type = ESPNOW_PROBE_JOB_ECHO;
      memcpy(job.mac, info->src_addr, 6);
      job.channel = frame.home;
      job.frame = frame;
      job.frame.rssi = rssi;
      job.frame.rx_channel = channel;
      if (pdTRUE != xQueueSend(EspNowProbe.jobs, &job, 0)) { EspNowProbe.queue_full++; }
      break;
    }
    case ESPNOW_PROBE_ECHO: {
      EspNowProbe.heard_echo++;
      EspNowProbeRun_t& run = EspNowProbe.run;
      if ((ESPNOW_PROBE_JOB_SEND == run.kind) && !run.done && (frame.seq >= run.first_seq) && (frame.seq <= run.last_seq)) {
        run.echoes++;
        EspNowProbeSpanAdd(&run.rtt, (uint32_t)esp_timer_get_time() - frame.sent_us);
      }
      break;
    }
    case ESPNOW_PROBE_BEACON:
      EspNowProbe.heard_beacon++;
      break;
  }
  return true;
}

// The mesh's send callback, first: true when the word is for the probe's send under way
bool EspNowProbeSendResult(const uint8_t* mac, bool ok);
bool EspNowProbeSendResult(const uint8_t* mac, bool ok) {
  if (!EspNowProbe.awaiting || memcmp(mac, EspNowProbe.send_to, 6)) { return false; }
  EspNowProbe.word_ok = ok;
  EspNowProbe.word_at = esp_timer_get_time();
  EspNowProbe.awaiting = false;
  if (EspNowProbe.word) { xSemaphoreGive(EspNowProbe.word); }
  return true;
}

// The mesh leaves the channel alone while the probe holds the radio somewhere else
bool EspNowProbeHoldsChannel(void);
bool EspNowProbeHoldsChannel(void) {
  return EspNowProbe.away;
}

// The end of a send away (WIFI_EVENT_ACTION_TX_STATUS) and of a listen (WIFI_EVENT_ROC_DONE): the radio is back on its channel
void EspNowProbeWifiEvent(void* arg, esp_event_base_t base, int32_t id, void* data);
void EspNowProbeWifiEvent(void* arg, esp_event_base_t base, int32_t id, void* data) {
  (void)arg;
  (void)base;
  EspNowProbe.back_at = esp_timer_get_time();
  if ((WIFI_EVENT_ACTION_TX_STATUS == id) && data) {
    EspNowProbe.back_status = ((wifi_event_action_tx_status_t*)data)->status;
  } else if ((WIFI_EVENT_ROC_DONE == id) && data) {
    EspNowProbe.back_status = ((wifi_event_roc_done_t*)data)->status;
  }
  if (EspNowProbe.back) { xSemaphoreGive(EspNowProbe.back); }
}

// The Wi-Fi events only counted: a scan done, a beacon timeout, a disconnection
void EspNowProbeCountEvent(void* arg, esp_event_base_t base, int32_t id, void* data);
void EspNowProbeCountEvent(void* arg, esp_event_base_t base, int32_t id, void* data) {
  (void)arg;
  (void)base;
  (void)data;
  switch (id) {
    case WIFI_EVENT_SCAN_DONE:          EspNowProbe.scan_done = EspNowProbe.scan_done + 1; break;
    case WIFI_EVENT_STA_BEACON_TIMEOUT: EspNowProbe.beacon_timeout = EspNowProbe.beacon_timeout + 1; break;
    case WIFI_EVENT_STA_DISCONNECTED:   EspNowProbe.disconnected = EspNowProbe.disconnected + 1; break;
  }
}

/*********************************************************************************************\
 * The task: sends, listens and echoes, with the mesh's radio lock
\*********************************************************************************************/

// The radio's word on a raw frame (esp_wifi_80211_tx): the nap's null frames are the only ones the firmware sends that way
void EspNowProbeNullDone(const esp_80211_tx_info_t* info);
void EspNowProbeNullDone(const esp_80211_tx_info_t* info) {
  EspNowProbe.null_ok = info && (WIFI_SEND_SUCCESS == info->tx_status);
  if (EspNowProbe.null_word) { xSemaphoreGive(EspNowProbe.null_word); }
}

static void EspNowProbeTxLocked(const uint8_t* to, uint8_t channel, uint16_t wait_ms, const uint8_t* data, size_t len, EspNowProbeTx_t* tx);
static void EspNowProbeTxLocked(const uint8_t* to, uint8_t channel, uint16_t wait_ms, const uint8_t* data, size_t len, EspNowProbeTx_t* tx) {
  uint8_t home = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  esp_wifi_get_channel(&home, &second);
  if (!esp_now_is_peer_exist(to) && !EspNowMeshAddPeer(to, millis())) {
    tx->err = ESP_ERR_ESPNOW_FULL;
    return;
  }
  tx->off = channel && (channel != home);
  xSemaphoreTake(EspNowProbe.word, 0);
  xSemaphoreTake(EspNowProbe.back, 0);
  memcpy(EspNowProbe.send_to, to, 6);
  EspNowProbe.word_ok = false;
  EspNowProbe.awaiting = true;
  int64_t start = esp_timer_get_time();
  if (tx->off) {
    esp_now_switch_channel_t* request = (esp_now_switch_channel_t*)calloc(1, sizeof(esp_now_switch_channel_t) + len);
    if (!request) {
      EspNowProbe.awaiting = false;
      tx->err = ESP_ERR_NO_MEM;
      return;
    }
    request->type = WIFI_OFFCHAN_TX_REQ;
    request->channel = channel;
    request->sec_channel = WIFI_SECOND_CHAN_NONE;
    request->wait_time_ms = wait_ms;
    memcpy(request->dest_mac, to, 6);
    request->data_len = len;
    memcpy(request->data, data, len);
    tx->err = esp_now_switch_channel_tx(request);
    free(request);
  } else {
    tx->err = esp_now_send(to, data, len);
  }
  tx->call_us = (uint32_t)(esp_timer_get_time() - start);
  if (ESP_OK != tx->err) {
    EspNowProbe.awaiting = false;
    return;
  }
  if (pdTRUE == xSemaphoreTake(EspNowProbe.word, pdMS_TO_TICKS(wait_ms + 100))) {
    tx->word = true;
    tx->ok = EspNowProbe.word_ok;
    tx->word_us = (uint32_t)(EspNowProbe.word_at - start);
  }
  EspNowProbe.awaiting = false;
  // The next send waits for the radio to be back: a request while it is still away would be refused, or cancel this one
  if (tx->off && (pdTRUE == xSemaphoreTake(EspNowProbe.back, pdMS_TO_TICKS(wait_ms + 200)))) {
    tx->back = true;
    tx->back_status = EspNowProbe.back_status;
    tx->back_us = (uint32_t)(EspNowProbe.back_at - start);
  }
}

// One frame, to one address, on one channel (0: the radio's)
static void EspNowProbeTx(const uint8_t* to, uint8_t channel, uint16_t wait_ms, const uint8_t* data, size_t len, EspNowProbeTx_t* tx);
static void EspNowProbeTx(const uint8_t* to, uint8_t channel, uint16_t wait_ms, const uint8_t* data, size_t len, EspNowProbeTx_t* tx) {
  memset(tx, 0, sizeof(EspNowProbeTx_t));
  tx->err = ESP_ERR_ESPNOW_NOT_INIT;
  if (!EspNowMeshDriver.radio || EspNowMeshDriver.radio_lost) { return; }
  if (!EspNowMeshRadioTake(100)) {
    tx->err = ESP_ERR_TIMEOUT;
    return;
  }
  if (EspNowMeshDriver.radio && !EspNowMeshDriver.radio_lost) { EspNowProbeTxLocked(to, channel, wait_ms, data, len, tx); }
  EspNowMeshRadioGive();
}

// A broadcast beacon by esp_now_send while the radio is on another channel by a remain-on-channel, with the lock already held: does the
// call take it, and does the radio say sent. Where it went out, the device listening on that channel says
static void EspNowProbeRocBeacon(uint8_t sent_on, EspNowProbeRocTx_t* tx);
static void EspNowProbeRocBeacon(uint8_t sent_on, EspNowProbeRocTx_t* tx) {
  uint8_t channel = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  if (ESP_OK == esp_wifi_get_channel(&channel, &second)) { tx->channel = channel; }
  if (!esp_now_is_peer_exist(EspNowProbeBroadcast) && !EspNowMeshAddPeer(EspNowProbeBroadcast, millis())) {
    tx->api_err++;
    tx->last_err = ESP_ERR_ESPNOW_FULL;
    return;
  }
  EspNowProbeFrame_t frame;
  memset(&frame, 0, sizeof(frame));
  frame.magic = ESPNOW_PROBE_MAGIC;
  frame.kind = ESPNOW_PROBE_BEACON;
  frame.home = channel;
  frame.sent_on = sent_on;
  EspNowProbe.seq = EspNowProbe.seq + 1;
  frame.seq = EspNowProbe.seq;
  frame.sent_us = (uint32_t)esp_timer_get_time();
  xSemaphoreTake(EspNowProbe.word, 0);
  memcpy(EspNowProbe.send_to, EspNowProbeBroadcast, 6);
  EspNowProbe.word_ok = false;
  EspNowProbe.awaiting = true;
  esp_err_t err = esp_now_send(EspNowProbeBroadcast, (const uint8_t*)&frame, sizeof(frame));
  tx->sent++;
  if (ESP_OK != err) {
    EspNowProbe.awaiting = false;
    tx->api_err++;
    tx->last_err = err;
    return;
  }
  if (pdTRUE == xSemaphoreTake(EspNowProbe.word, pdMS_TO_TICKS(100))) {
    if (EspNowProbe.word_ok) { tx->acked++; } else { tx->nacked++; }
  } else {
    tx->no_word++;
  }
  EspNowProbe.awaiting = false;
}

static void EspNowProbeFill(EspNowProbeFrame_t* frame, uint8_t kind, uint8_t sent_on);
static void EspNowProbeFill(EspNowProbeFrame_t* frame, uint8_t kind, uint8_t sent_on) {
  uint8_t home = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  esp_wifi_get_channel(&home, &second);
  memset(frame, 0, sizeof(EspNowProbeFrame_t));
  frame->magic = ESPNOW_PROBE_MAGIC;
  frame->kind = kind;
  frame->home = home;
  frame->sent_on = sent_on ? sent_on : home;
  EspNowProbe.seq = EspNowProbe.seq + 1;
  frame->seq = EspNowProbe.seq;
}

static bool EspNowProbeAssociated(void) {
  wifi_ap_record_t ap;
  return (ESP_OK == esp_wifi_sta_get_ap_info(&ap));
}

static void EspNowProbeDo(const EspNowProbeJob_t* job);

// The echo of a probe heard, on the channel its sender lives on
static void EspNowProbeEcho(const EspNowProbeJob_t* job);
static void EspNowProbeEcho(const EspNowProbeJob_t* job) {
  EspNowProbeFrame_t frame = job->frame;
  frame.kind = ESPNOW_PROBE_ECHO;
  frame.heard = EspNowProbe.heard_probe;
  uint8_t home = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  esp_wifi_get_channel(&home, &second);
  frame.home = home;
  frame.sent_on = job->channel;
  EspNowProbeTx_t tx;
  EspNowProbeTx(job->mac, job->channel, 10, (const uint8_t*)&frame, sizeof(frame), &tx);
  if ((ESP_OK == tx.err) && tx.ok) {
    EspNowProbe.echo_sent++;
  } else {
    EspNowProbe.echo_failed++;
    EspNowProbe.echo_err = (ESP_OK != tx.err) ? tx.err : -1;
  }
}

static void EspNowProbeBeacon(void) {
  EspNowProbeFrame_t frame;
  EspNowProbeFill(&frame, ESPNOW_PROBE_BEACON, 0);
  EspNowProbeTx_t tx;
  EspNowProbeTx(EspNowProbeBroadcast, 0, 10, (const uint8_t*)&frame, sizeof(frame), &tx);
  if ((ESP_OK == tx.err) && tx.ok) { EspNowProbe.beacon_sent++; } else { EspNowProbe.beacon_failed++; }
}

// Until `until` (millis), the echoes asked for meanwhile are sent; a run asked for meanwhile was refused by the command
static void EspNowProbeServeUntil(uint32_t until) {
  EspNowProbeJob_t other;
  for (;;) {
    int32_t left = (int32_t)(until - millis());
    if (left <= 0) { return; }
    if ((pdTRUE == xQueueReceive(EspNowProbe.jobs, &other, pdMS_TO_TICKS(left))) && (ESPNOW_PROBE_JOB_ECHO == other.type)) {
      EspNowProbeEcho(&other);
    }
  }
}

static void EspNowProbeSendRun(const EspNowProbeJob_t* job);
static void EspNowProbeSendRun(const EspNowProbeJob_t* job) {
  EspNowProbeRun_t& run = EspNowProbe.run;
  bool broadcast = !memcmp(job->mac, EspNowProbeBroadcast, 6);
  uint8_t buffer[ESPNOW_PROBE_MAX_FRAME];
  memset(buffer, 0, sizeof(buffer));
  uint32_t started = millis();
  run.first_seq = EspNowProbe.seq + 1;
  for (uint32_t i = 0; i < job->count; i++) {
    uint32_t due = millis() + job->interval_ms;
    EspNowProbeFrame_t frame;
    EspNowProbeFill(&frame, ESPNOW_PROBE_PROBE, job->channel);
    run.last_seq = frame.seq;
    frame.sent_us = (uint32_t)esp_timer_get_time();
    memcpy(buffer, &frame, sizeof(frame));
    EspNowProbeTx_t tx;
    EspNowProbeTx(job->mac, job->channel, job->wait_ms, buffer, job->size, &tx);
    run.sent++;
    if (tx.call_us > run.call_us_max) { run.call_us_max = tx.call_us; }
    if (ESP_OK != tx.err) {
      run.api_err++;
      run.last_err = tx.err;
    } else {
      if (!tx.word) {
        run.no_word++;
      } else {
        if (tx.ok) { run.acked++; } else { run.nacked++; }
        EspNowProbeSpanAdd(&run.word, tx.word_us);
      }
      if (tx.off) {
        if (!tx.back) {
          run.no_back++;
        } else {
          if (WIFI_ACTION_TX_OP_CANCELLED == tx.back_status) { run.cancelled++; } else { run.back++; }
          EspNowProbeSpanAdd(&run.away, tx.back_us);
        }
      }
    }
    EspNowProbeServeUntil(due);
  }
  if (!broadcast) { EspNowProbeServeUntil(millis() + ESPNOW_PROBE_ECHO_WAIT_MS); }
  run.ms = millis() - started;
}

static void EspNowProbeListenRun(const EspNowProbeJob_t* job);
static void EspNowProbeListenRun(const EspNowProbeJob_t* job) {
  EspNowProbeRun_t& run = EspNowProbe.run;
  uint32_t started = millis();
  run.roc_err = ESP_ERR_ESPNOW_NOT_INIT;
  if (EspNowMeshDriver.radio && !EspNowMeshDriver.radio_lost && EspNowMeshRadioTake(100)) {
    // The lock is held through the listen: no frame of the mesh goes out while the radio is on the other channel
    EspNowProbe.listen_channel = job->channel;
    EspNowProbe.listen_heard = 0;
    EspNowProbe.listening = true;
    xSemaphoreTake(EspNowProbe.back, 0);
    esp_now_remain_on_channel_t request;
    memset(&request, 0, sizeof(request));
    request.type = WIFI_ROC_REQ;
    request.channel = job->channel;
    request.sec_channel = WIFI_SECOND_CHAN_NONE;
    request.wait_time_ms = job->interval_ms;
    int64_t start = esp_timer_get_time();
    run.roc_err = esp_now_remain_on_channel(&request);
    if (ESP_OK == run.roc_err) {
      // The beacons asked for go out while the radio is there, until the listen ends
      uint32_t beacons = job->count;
      uint32_t next = millis() + ESPNOW_PROBE_ROC_TX_DELAY_MS;
      for (;;) {
        int32_t left = (int32_t)(next - millis());
        if (!beacons) { left = job->interval_ms + 500; }
        if (left < 0) { left = 0; }
        if (pdTRUE == xSemaphoreTake(EspNowProbe.back, pdMS_TO_TICKS(left))) {
          run.roc_done = true;
          run.roc_us = (uint32_t)(EspNowProbe.back_at - start);
          break;
        }
        if (!beacons) { break; }
        if ((int32_t)(millis() - next) >= 0) {
          EspNowProbeRocBeacon(job->channel, &run.tx);
          beacons--;
          next = millis() + job->tx_interval_ms;
        }
      }
    }
    EspNowProbe.listening = false;
    run.heard = EspNowProbe.listen_heard;
    EspNowMeshRadioGive();
  }
  run.ms = millis() - started;
}

// A null data frame to the access point, with the power management bit set (the station dozes, and the access point keeps its frames)
// or clear (awake again, and the access point sends what it kept): what a station's driver says before it leaves its channel, and once
// it is back
static void EspNowProbeNull(const uint8_t* bssid, bool doze, EspNowProbeNull_t* null);
static void EspNowProbeNull(const uint8_t* bssid, bool doze, EspNowProbeNull_t* null) {
  uint8_t frame[24];
  memset(frame, 0, sizeof(frame));
  frame[0] = 0x48;                         // a data frame of the null function subtype
  frame[1] = doze ? 0x11 : 0x01;           // to the distribution system, with the power management bit or without it
  memcpy(&frame[4], bssid, 6);             // to the access point
  esp_wifi_get_mac(WIFI_IF_STA, &frame[10]);
  memcpy(&frame[16], bssid, 6);
  xSemaphoreTake(EspNowProbe.null_word, 0);
  EspNowProbe.null_ok = false;
  esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), true);
  if (ESP_OK != err) {
    null->api_err++;
    null->last_err = err;
    return;
  }
  null->sent++;
  if (pdTRUE != xSemaphoreTake(EspNowProbe.null_word, pdMS_TO_TICKS(ESPNOW_PROBE_NAP_PS_WAIT_MS))) {
    null->no_word++;
    return;
  }
  if (EspNowProbe.null_ok) { null->acked++; } else { null->failed++; }
}

// Until a TSF time (µs of the station's clock), serving the echoes meanwhile; false when the TSF cannot be read
static bool EspNowProbeNapUntil(int64_t tsf_until);
static bool EspNowProbeNapUntil(int64_t tsf_until) {
  for (;;) {
    int64_t tsf = esp_wifi_get_tsf_time(WIFI_IF_STA);
    if (tsf <= 0) { return false; }
    int64_t left_us = tsf_until - tsf;
    if (left_us <= 0) { return true; }
    uint32_t left_ms = (uint32_t)((left_us + 999) / 1000);
    EspNowProbeServeUntil(millis() + ((left_ms > 1000) ? 1000 : left_ms));
  }
}

// A station that lives on another channel and naps on its access point: the island node of a multi-channel mesh, in probe form
static void EspNowProbeNapRun(const EspNowProbeJob_t* job);
static void EspNowProbeNapRun(const EspNowProbeJob_t* job) {
  EspNowProbeRun_t& run = EspNowProbe.run;
  uint32_t started = millis();
  uint32_t until = started + (uint32_t)job->seconds * 1000;
  int64_t bi_us = (int64_t)job->beacon_tu * 1024;
  int64_t period_us = bi_us * job->count;
  int64_t home_us = (int64_t)job->interval_ms * 1000;
  EspNowProbe.stop = false;
  EspNowProbe.listen_channel = job->channel;
  EspNowProbe.listen_heard = 0;
  uint8_t bssid[6] = { 0 };
  if (job->ps && EspNowProbe.null_word) {
    wifi_ap_record_t ap;
    if (ESP_OK == esp_wifi_sta_get_ap_info(&ap)) {
      memcpy(bssid, ap.bssid, 6);
      run.ps = true;
    }
  }
  while (!EspNowProbe.stop && ((int32_t)(until - millis()) > 0)) {
    int64_t tsf = esp_wifi_get_tsf_time(WIFI_IF_STA);
    if (tsf <= 0) {
      run.tsf_lost++;
      EspNowProbeServeUntil(millis() + 1000);
      continue;
    }
    // Home now. The beacon comes at the next TBTT; the radio stays home_us past it, then goes to the channel until just before the TBTT
    // that ends the period
    int64_t tbtt = ((tsf / bi_us) + 1) * bi_us;
    if (!EspNowProbeNapUntil(tbtt + home_us)) { run.tsf_lost++; continue; }
    int64_t return_at = tbtt + period_us - ESPNOW_PROBE_NAP_GUARD_US;
    int64_t now = esp_wifi_get_tsf_time(WIFI_IF_STA);
    int64_t wait_us = return_at - now - ESPNOW_PROBE_NAP_LEAVE_US;
    if (wait_us < (int64_t)ESPNOW_PROBE_NAP_MIN_WAIT_MS * 1000) {
      run.skipped++;
      continue;
    }
    if (!EspNowMeshDriver.radio || EspNowMeshDriver.radio_lost || !EspNowMeshRadioTake(100)) {
      run.skipped++;
      EspNowProbeServeUntil(millis() + 10);
      continue;
    }
    // The lock is held while the radio is away: no frame of the mesh goes out on the wrong channel. It is given back for the time home
    if (run.ps) {
      EspNowProbeNull(bssid, true, &run.null);
      // The stay is what is left after the null frame
      wait_us = return_at - esp_wifi_get_tsf_time(WIFI_IF_STA) - ESPNOW_PROBE_NAP_LEAVE_US;
      if (wait_us < (int64_t)ESPNOW_PROBE_NAP_MIN_WAIT_MS * 1000) {
        EspNowProbeNull(bssid, false, &run.null);
        EspNowMeshRadioGive();
        run.skipped++;
        continue;
      }
    }
    EspNowProbe.listening = true;
    xSemaphoreTake(EspNowProbe.back, 0);
    esp_now_remain_on_channel_t request;
    memset(&request, 0, sizeof(request));
    request.type = WIFI_ROC_REQ;
    request.channel = job->channel;
    request.sec_channel = WIFI_SECOND_CHAN_NONE;
    request.wait_time_ms = (uint32_t)(wait_us / 1000);
    int64_t start = esp_timer_get_time();
    esp_err_t err = esp_now_remain_on_channel(&request);
    if (ESP_OK != err) {
      run.roc_refused++;
      run.roc_err = err;
    } else {
      run.periods++;
      bool back = false;
      if (job->tx) {
        // The beacon on the channel, once the radio should be there; a return before that ends the wait
        if (pdTRUE == xSemaphoreTake(EspNowProbe.back, pdMS_TO_TICKS(ESPNOW_PROBE_ROC_TX_DELAY_MS))) {
          back = true;
        } else {
          EspNowProbeRocBeacon(job->channel, &run.tx);
        }
      }
      if (!back) { back = (pdTRUE == xSemaphoreTake(EspNowProbe.back, pdMS_TO_TICKS(request.wait_time_ms + 500))); }
      if (!back) {
        run.roc_no_back++;
      } else {
        if (WIFI_ROC_DONE != EspNowProbe.back_status) { run.roc_cancelled++; }
        uint32_t away_us = (uint32_t)(EspNowProbe.back_at - start);
        EspNowProbeSpanAdd(&run.away, away_us);
        // How late the radio was back, against the plan: the TSF now, less the time since the event
        int64_t back_tsf = esp_wifi_get_tsf_time(WIFI_IF_STA) - (esp_timer_get_time() - EspNowProbe.back_at);
        int64_t late_us = back_tsf - return_at;
        if (late_us > 0) { EspNowProbeSpanAdd(&run.late_us, (uint32_t)late_us); }
        if (back_tsf > (return_at + ESPNOW_PROBE_NAP_GUARD_US)) { run.late++; }
      }
    }
    EspNowProbe.listening = false;
    if (run.ps) { EspNowProbeNull(bssid, false, &run.null); }
    EspNowMeshRadioGive();
  }
  run.heard = EspNowProbe.listen_heard;
  run.ms = millis() - started;
}

static void EspNowProbeDo(const EspNowProbeJob_t* job) {
  switch (job->type) {
    case ESPNOW_PROBE_JOB_ECHO:
      EspNowProbeEcho(job);
      break;
    case ESPNOW_PROBE_JOB_SEND:
    case ESPNOW_PROBE_JOB_LISTEN:
    case ESPNOW_PROBE_JOB_NAP: {
      EspNowProbeRun_t& run = EspNowProbe.run;
      memset(&run, 0, sizeof(run));
      run.kind = job->type;
      memcpy(run.mac, job->mac, 6);
      run.channel = job->channel;
      run.home = EspNowProbe.home;
      run.associated = EspNowProbeAssociated();
      run.count = job->count;
      run.interval_ms = job->interval_ms;
      run.wait_ms = job->wait_ms;
      run.size = job->size;
      run.home_ms = job->interval_ms;
      run.beacon_tu = job->beacon_tu;
      run.seconds = job->seconds;
      if (ESPNOW_PROBE_JOB_SEND == job->type) {
        EspNowProbeSendRun(job);
      } else if (ESPNOW_PROBE_JOB_LISTEN == job->type) {
        EspNowProbeListenRun(job);
      } else {
        EspNowProbeNapRun(job);
      }
      run.done = true;
      EspNowProbe.busy = false;
      break;
    }
  }
}

static void EspNowProbeTask(void* argument) {
  (void)argument;
  EspNowProbeJob_t job;
  uint32_t next_beacon = millis();
  for (;;) {
    TickType_t wait = portMAX_DELAY;
    bool beacons = EspNowProbe.away_on && EspNowProbe.beacon_ms;
    if (beacons) {
      int32_t left = (int32_t)(next_beacon - millis());
      wait = (left > 0) ? pdMS_TO_TICKS(left) : 0;
    }
    if (pdTRUE == xQueueReceive(EspNowProbe.jobs, &job, wait)) { EspNowProbeDo(&job); }
    if (EspNowProbe.away_on && EspNowProbe.beacon_ms && ((int32_t)(millis() - next_beacon) >= 0)) {
      next_beacon = millis() + EspNowProbe.beacon_ms;
      EspNowProbeBeacon();
    }
  }
}

/*********************************************************************************************\
 * The main loop
\*********************************************************************************************/

static bool EspNowProbeStart(void) {
  if (EspNowProbe.task) { return true; }
  EspNowProbe.jobs = xQueueCreate(ESPNOW_PROBE_JOBS, sizeof(EspNowProbeJob_t));
  EspNowProbe.word = xSemaphoreCreateBinary();
  EspNowProbe.back = xSemaphoreCreateBinary();
  EspNowProbe.null_word = xSemaphoreCreateBinary();
  if (!EspNowProbe.jobs || !EspNowProbe.word || !EspNowProbe.back || !EspNowProbe.null_word) {
    AddLog(LOG_LEVEL_ERROR, PSTR("EPR: No memory for the probe"));
    return false;
  }
  if (pdPASS != xTaskCreate(EspNowProbeTask, "espnow_probe", ESPNOW_PROBE_TASK_STACK, nullptr, ESPNOW_PROBE_TASK_PRIORITY, &EspNowProbe.task)) {
    EspNowProbe.task = nullptr;
    AddLog(LOG_LEVEL_ERROR, PSTR("EPR: The probe's task did not start"));
    return false;
  }
  return true;
}

// The default event loop is there once the WiFi has started: the handlers are registered from the first tick that finds it
static void EspNowProbeEvents(void) {
  if (EspNowProbe.events || (WIFI_OFF == WiFi.getMode())) { return; }
  esp_err_t a = esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_ACTION_TX_STATUS, &EspNowProbeWifiEvent, nullptr, nullptr);
  esp_err_t b = esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_ROC_DONE, &EspNowProbeWifiEvent, nullptr, nullptr);
  esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &EspNowProbeCountEvent, nullptr, nullptr);
  esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_BEACON_TIMEOUT, &EspNowProbeCountEvent, nullptr, nullptr);
  esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &EspNowProbeCountEvent, nullptr, nullptr);
  esp_wifi_register_80211_tx_cb(&EspNowProbeNullDone);
  EspNowProbe.events = (ESP_OK == a) && (ESP_OK == b);
}

static void EspNowProbeRocTxJson(const EspNowProbeRocTx_t* tx);
static void EspNowProbeRocTxJson(const EspNowProbeRocTx_t* tx) {
  ResponseAppend_P(PSTR(",\"Tx\":{\"Sent\":%u,\"ApiErr\":%u,\"Err\":%d,\"Acked\":%u,\"Nacked\":%u,\"NoWord\":%u,\"Channel\":%u}"),
    tx->sent, tx->api_err, tx->last_err, tx->acked, tx->nacked, tx->no_word, tx->channel);
}

static void EspNowProbeSpanJson(const char* name, const EspNowProbeSpan_t* span);
static void EspNowProbeSpanJson(const char* name, const EspNowProbeSpan_t* span) {
  ResponseAppend_P(PSTR(",\"%s\":[%u,%u,%u]"), name, span->n ? span->min : 0, span->n ? (uint32_t)(span->sum / span->n) : 0, span->max);
}

static void EspNowProbeRunJson(void) {
  const EspNowProbeRun_t& run = EspNowProbe.run;
  if (!run.kind) {
    ResponseAppend_P(PSTR("null"));
    return;
  }
  char mac[18];
  ToHex_P(run.mac, 6, mac, sizeof(mac), ':');
  if (ESPNOW_PROBE_JOB_LISTEN == run.kind) {
    ResponseAppend_P(PSTR("{\"Kind\":\"Listen\",\"Channel\":%u,\"Home\":%u,\"Associated\":%u,\"WaitMs\":%u,\"Err\":%d,\"RocDone\":%u,\"RocUs\":%u,\"Heard\":%u"),
      run.channel, run.home, run.associated, run.interval_ms, run.roc_err, run.roc_done, run.roc_us, run.heard);
    EspNowProbeRocTxJson(&run.tx);
    ResponseAppend_P(PSTR(",\"Ms\":%u,\"Done\":%u}"), run.ms, run.done);
    return;
  }
  if (ESPNOW_PROBE_JOB_NAP == run.kind) {
    ResponseAppend_P(PSTR("{\"Kind\":\"Nap\",\"Channel\":%u,\"Home\":%u,\"Associated\":%u,\"Beacons\":%u,\"HomeMs\":%u,\"BeaconTu\":%u,\"Seconds\":%u,"
                          "\"Periods\":%u,\"Skipped\":%u,\"RocRefused\":%u,\"RocErr\":%d,\"RocCancelled\":%u,\"NoBack\":%u,\"TsfLost\":%u,\"Late\":%u"),
      run.channel, run.home, run.associated, run.count, run.home_ms, run.beacon_tu, run.seconds,
      run.periods, run.skipped, run.roc_refused, run.roc_err, run.roc_cancelled, run.roc_no_back, run.tsf_lost, run.late);
    EspNowProbeSpanJson(PSTR("AwayUs"), &run.away);
    EspNowProbeSpanJson(PSTR("LateUs"), &run.late_us);
    ResponseAppend_P(PSTR(",\"Heard\":%u"), run.heard);
    EspNowProbeRocTxJson(&run.tx);
    if (run.ps) {
      ResponseAppend_P(PSTR(",\"Ps\":{\"Sent\":%u,\"ApiErr\":%u,\"Err\":%d,\"Acked\":%u,\"Failed\":%u,\"NoWord\":%u}"),
        run.null.sent, run.null.api_err, run.null.last_err, run.null.acked, run.null.failed, run.null.no_word);
    }
    ResponseAppend_P(PSTR(",\"ScanDone\":%u,\"BeaconTimeout\":%u,\"Disconnected\":%u,\"Ms\":%u,\"Done\":%u}"),
      EspNowProbe.scan_done, EspNowProbe.beacon_timeout, EspNowProbe.disconnected, run.ms, run.done);
    return;
  }
  ResponseAppend_P(PSTR("{\"Kind\":\"Send\",\"To\":\"%s\",\"Channel\":%u,\"Home\":%u,\"Associated\":%u,\"Count\":%u,\"IntervalMs\":%u,\"WaitMs\":%u,\"Size\":%u,"
                        "\"Sent\":%u,\"ApiErr\":%u,\"Err\":%d,\"Acked\":%u,\"Nacked\":%u,\"NoWord\":%u,\"Back\":%u,\"Cancelled\":%u,\"NoBack\":%u,\"CallUsMax\":%u"),
    mac, run.channel, run.home, run.associated, run.count, run.interval_ms, run.wait_ms, run.size,
    run.sent, run.api_err, run.last_err, run.acked, run.nacked, run.no_word, run.back, run.cancelled, run.no_back, run.call_us_max);
  EspNowProbeSpanJson(PSTR("WordUs"), &run.word);
  EspNowProbeSpanJson(PSTR("AwayUs"), &run.away);
  ResponseAppend_P(PSTR(",\"Echoes\":%u"), run.echoes);
  EspNowProbeSpanJson(PSTR("RttUs"), &run.rtt);
  ResponseAppend_P(PSTR(",\"Ms\":%u,\"Done\":%u}"), run.ms, run.done);
}

static void EspNowProbeAwayEnd(void) {
  EspNowProbe.away_on = false;
  EspNowProbe.away = false;
  EspNowProbe.away_paused = false;
  StaCtrlRadioRelease();
  Response_P(PSTR("{\"EspNowProbeAway\":{\"State\":\"Back\",\"Channel\":%u,\"Seconds\":%u,\"Probes\":%u,\"Echoes\":%u,\"Beacons\":%u,\"EchoFailed\":%u,\"BeaconFailed\":%u}}"),
    EspNowProbe.away_channel, (millis() - EspNowProbe.away_since) / 1000, EspNowProbe.heard_probe - EspNowProbe.away_probes,
    EspNowProbe.echo_sent - EspNowProbe.away_echoes, EspNowProbe.beacon_sent - EspNowProbe.away_beacons, EspNowProbe.echo_failed, EspNowProbe.beacon_failed);
  AddLog(LOG_LEVEL_INFO, PSTR("EPR: %s"), ResponseData());
  XdrvRulesProcess(0);
}

static void EspNowProbeEvery100ms(void) {
  if (!EspNowProbe.task) { return; }
  EspNowProbeEvents();
  uint8_t channel = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  if ((WiFi.getMode() & WIFI_MODE_STA) && (ESP_OK == esp_wifi_get_channel(&channel, &second))) {
    EspNowProbe.home = channel;
    // The ticks the radio is off the mesh's channel, with no run holding it elsewhere: a station scanning for a network it cannot reach
    if (EspNowMeshSettings.channel && !EspNowProbe.away && !EspNowProbe.busy) {
      EspNowProbe.ticks++;
      if (channel != EspNowMeshSettings.channel) { EspNowProbe.off_ticks++; }
    }
  }
  if (EspNowProbe.away && !EspNowProbe.away_paused) {
    if ((int32_t)(millis() - EspNowProbe.away_since) >= 300) {
      EspNowProbe.away_paused = true;
      StaCtrlRadioPause();
    }
  } else if (EspNowProbe.away) {
    if ((int32_t)(millis() - EspNowProbe.away_until) >= 0) {
      EspNowProbeAwayEnd();
    } else if (!EspNowProbeAssociated() && (WiFi.getMode() & WIFI_MODE_STA)) {
      // The WiFi stack stops and starts again on the way out of the network: the channel is put in place, and again, until it stays
      if (channel != EspNowProbe.away_channel) {
        EspNowProbe.away_on = false;
        if (ESP_OK == esp_wifi_set_channel(EspNowProbe.away_channel, WIFI_SECOND_CHAN_NONE)) {
          AddLog(LOG_LEVEL_INFO, PSTR("EPR: Away, the radio from channel %u to %u"), channel, EspNowProbe.away_channel);
        }
      } else if (!EspNowProbe.away_on) {
        EspNowProbe.away_on = true;
        EspNowProbeJob_t wake;
        memset(&wake, 0, sizeof(wake));
        wake.type = ESPNOW_PROBE_JOB_WAKE;
        xQueueSend(EspNowProbe.jobs, &wake, 0);
      }
    }
  }
  EspNowProbeRun_t& run = EspNowProbe.run;
  if (run.kind && run.done && !run.reported) {
    run.reported = true;
    Response_P(PSTR("{\"EspNowProbe\":"));
    EspNowProbeRunJson();
    ResponseJsonEnd();
    AddLog(LOG_LEVEL_INFO, PSTR("EPR: %s"), ResponseData());
    XdrvRulesProcess(0);
  }
}

static bool EspNowProbeMac(const char* text, uint8_t* mac) {
  unsigned int m[6];
  if (6 != sscanf(text, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5])) { return false; }
  for (uint32_t i = 0; i < 6; i++) {
    if (m[i] > 0xFF) { return false; }
    mac[i] = m[i];
  }
  return true;
}

// Splits the command's argument at its commas, in place: how many fields
static uint32_t EspNowProbeFields(char* text, char** fields, uint32_t max) {
  uint32_t count = 0;
  if (!*text) { return 0; }
  fields[count++] = text;
  for (char* p = text; *p && (count < max); p++) {
    if (',' == *p) { *p = '\0'; fields[count++] = p + 1; }
  }
  return count;
}

static bool EspNowProbeReady(void) {
  if (!EspNowProbeStart()) {
    ResponseCmndChar_P(PSTR("no memory"));
    return false;
  }
  if (!EspNowMeshDriver.radio || EspNowMeshDriver.radio_lost) {
    ResponseCmndChar_P(PSTR("the mesh's radio is not up"));
    return false;
  }
  if (EspNowProbe.busy) {
    ResponseCmndChar_P(PSTR("busy"));
    return false;
  }
  return true;
}

void CmndEspNowProbe(void) {
  EspNowProbeStart();
  if (XdrvMailbox.data_len && (0 == XdrvMailbox.payload)) {
    EspNowProbe.heard_probe = EspNowProbe.heard_echo = EspNowProbe.heard_beacon = EspNowProbe.heard_off = 0;
    EspNowProbe.echo_err = 0;
    EspNowProbe.echo_sent = EspNowProbe.echo_failed = EspNowProbe.beacon_sent = EspNowProbe.beacon_failed = EspNowProbe.queue_full = 0;
    EspNowProbe.scan_done = EspNowProbe.beacon_timeout = EspNowProbe.disconnected = 0;
    EspNowProbe.ticks = EspNowProbe.off_ticks = 0;
  }
  Response_P(PSTR("{\"%s\":{\"Channel\":%u,\"Associated\":%u,\"Away\":%u,\"Busy\":%u,\"Events\":%u,"
                  "\"Heard\":{\"Probe\":%u,\"Echo\":%u,\"Beacon\":%u,\"OffChannel\":%u,\"Rssi\":%d,\"RxChannel\":%u},"
                  "\"Echoes\":{\"Sent\":%u,\"Failed\":%u,\"Err\":%d},\"Beacons\":{\"Sent\":%u,\"Failed\":%u},\"QueueFull\":%u,"
                  "\"Radio\":{\"MeshChannel\":%u,\"Ticks\":%u,\"OffTicks\":%u},\"Wifi\":{\"ScanDone\":%u,\"BeaconTimeout\":%u,\"Disconnected\":%u},\"Last\":"),
    XdrvMailbox.command, EspNowProbe.home, EspNowProbeAssociated(), EspNowProbe.away, EspNowProbe.busy, EspNowProbe.events,
    EspNowProbe.heard_probe, EspNowProbe.heard_echo, EspNowProbe.heard_beacon, EspNowProbe.heard_off, EspNowProbe.last_rssi, EspNowProbe.last_channel,
    EspNowProbe.echo_sent, EspNowProbe.echo_failed, EspNowProbe.echo_err, EspNowProbe.beacon_sent, EspNowProbe.beacon_failed, EspNowProbe.queue_full,
    EspNowMeshSettings.channel, EspNowProbe.ticks, EspNowProbe.off_ticks, EspNowProbe.scan_done, EspNowProbe.beacon_timeout, EspNowProbe.disconnected);
  if (EspNowProbe.busy) { ResponseAppend_P(PSTR("null")); } else { EspNowProbeRunJson(); }
  ResponseAppend_P(PSTR("}}"));
}

void CmndEspNowProbeSend(void) {
  char text[96];
  snprintf(text, sizeof(text), "%s", XdrvMailbox.data);
  char* fields[6];
  uint32_t count = EspNowProbeFields(text, fields, 6);
  EspNowProbeJob_t job;
  memset(&job, 0, sizeof(job));
  if ((count < 2) || !EspNowProbeMac(fields[0], job.mac)) {
    ResponseCmndError();
    return;
  }
  uint32_t channel = atoi(fields[1]);
  job.type = ESPNOW_PROBE_JOB_SEND;
  job.channel = channel;
  job.count = (count > 2) ? atoi(fields[2]) : 10;
  job.interval_ms = (count > 3) ? atoi(fields[3]) : 100;
  job.wait_ms = (count > 4) ? atoi(fields[4]) : 10;
  job.size = (count > 5) ? atoi(fields[5]) : sizeof(EspNowProbeFrame_t);
  if ((channel > 13) || !job.count || (job.count > 10000) || (job.interval_ms > 60000) || !job.wait_ms || (job.wait_ms > 1000) ||
      (job.size < sizeof(EspNowProbeFrame_t)) || (job.size > ESPNOW_PROBE_MAX_FRAME)) {
    ResponseCmndError();
    return;
  }
  if (!EspNowProbeReady()) { return; }
  EspNowProbe.busy = true;
  if (pdTRUE != xQueueSend(EspNowProbe.jobs, &job, 0)) {
    EspNowProbe.busy = false;
    ResponseCmndChar_P(PSTR("busy"));
    return;
  }
  ResponseCmndChar_P(PSTR("Started"));
}

void CmndEspNowProbeListen(void) {
  char text[48];
  snprintf(text, sizeof(text), "%s", XdrvMailbox.data);
  char* fields[4];
  uint32_t count = EspNowProbeFields(text, fields, 4);
  if (count < 2) {
    ResponseCmndError();
    return;
  }
  EspNowProbeJob_t job;
  memset(&job, 0, sizeof(job));
  job.type = ESPNOW_PROBE_JOB_LISTEN;
  job.channel = atoi(fields[0]);
  job.interval_ms = atoi(fields[1]);
  job.count = (count > 2) ? atoi(fields[2]) : 0;
  job.tx_interval_ms = (count > 3) ? atoi(fields[3]) : 50;
  if (!job.channel || (job.channel > 13) || !job.interval_ms || (job.interval_ms > 10000) || (job.count > 1000) || (job.tx_interval_ms < 10)) {
    ResponseCmndError();
    return;
  }
  if (!EspNowProbeReady()) { return; }
  EspNowProbe.busy = true;
  if (pdTRUE != xQueueSend(EspNowProbe.jobs, &job, 0)) {
    EspNowProbe.busy = false;
    ResponseCmndChar_P(PSTR("busy"));
    return;
  }
  ResponseCmndChar_P(PSTR("Started"));
}

void CmndEspNowProbeNap(void) {
  if (XdrvMailbox.data_len && (0 == XdrvMailbox.payload)) {
    EspNowProbe.stop = true;
    ResponseCmndChar_P(PSTR("Stopping"));
    return;
  }
  char text[48];
  snprintf(text, sizeof(text), "%s", XdrvMailbox.data);
  char* fields[7];
  uint32_t count = EspNowProbeFields(text, fields, 7);
  if (count < 3) {
    ResponseCmndError();
    return;
  }
  EspNowProbeJob_t job;
  memset(&job, 0, sizeof(job));
  job.type = ESPNOW_PROBE_JOB_NAP;
  job.channel = atoi(fields[0]);
  job.count = atoi(fields[1]);
  job.interval_ms = atoi(fields[2]);
  job.seconds = (count > 3) ? atoi(fields[3]) : 60;
  job.tx = (count > 4) ? (atoi(fields[4]) ? 1 : 0) : 0;
  job.beacon_tu = (count > 5) ? atoi(fields[5]) : 100;
  job.ps = (count > 6) ? (atoi(fields[6]) ? 1 : 0) : 0;
  if (!job.channel || (job.channel > 13) || !job.count || (job.count > 10) || (job.interval_ms < 5) || (job.interval_ms > 2000) ||
      !job.seconds || (job.seconds > ESPNOW_PROBE_NAP_MAX_S) || (job.beacon_tu < 20) || (job.beacon_tu > 1000) ||
      (job.interval_ms + ESPNOW_PROBE_NAP_MIN_WAIT_MS + (ESPNOW_PROBE_NAP_LEAVE_US + ESPNOW_PROBE_NAP_GUARD_US) / 1000 >= job.count * job.beacon_tu * 1024 / 1000)) {
    ResponseCmndError();
    return;
  }
  if (!EspNowProbeReady()) { return; }
  if (!EspNowProbeAssociated()) {
    ResponseCmndChar_P(PSTR("not associated"));
    return;
  }
  if (job.channel == EspNowProbe.home) {
    ResponseCmndChar_P(PSTR("that is the station's channel"));
    return;
  }
  EspNowProbe.busy = true;
  if (pdTRUE != xQueueSend(EspNowProbe.jobs, &job, 0)) {
    EspNowProbe.busy = false;
    ResponseCmndChar_P(PSTR("busy"));
    return;
  }
  ResponseCmndChar_P(PSTR("Started"));
}

void CmndEspNowProbeAway(void) {
#ifdef USE_WIFI_STATION_CONTROL
  char text[32];
  snprintf(text, sizeof(text), "%s", XdrvMailbox.data);
  char* fields[3];
  uint32_t count = EspNowProbeFields(text, fields, 3);
  if (count < 2) {
    ResponseCmndError();
    return;
  }
  uint32_t channel = atoi(fields[0]);
  uint32_t seconds = atoi(fields[1]);
  uint32_t beacon = (count > 2) ? atoi(fields[2]) : 0;
  if (!channel || (channel > 13) || !seconds || (seconds > ESPNOW_PROBE_AWAY_MAX_S) || (beacon && (beacon < 10)) || (beacon > 10000)) {
    ResponseCmndError();
    return;
  }
  if (!EspNowProbeReady()) { return; }
  if (EspNowProbe.away) {
    ResponseCmndChar_P(PSTR("already away"));
    return;
  }
  if (!StaCtrlRadioClaim()) {
    Response_P(PSTR("{\"%s\":\"Busy\",\"Owner\":\"%s\"}"), XdrvMailbox.command, StaCtrlRadioOwnerText(StaCtrlRadioOwner()));
    return;
  }
  EspNowProbe.away_channel = channel;
  EspNowProbe.beacon_ms = beacon;
  EspNowProbe.away_since = millis();
  EspNowProbe.away_until = millis() + seconds * 1000;
  EspNowProbe.away_probes = EspNowProbe.heard_probe;
  EspNowProbe.away_echoes = EspNowProbe.echo_sent;
  EspNowProbe.away_beacons = EspNowProbe.beacon_sent;
  EspNowProbe.away_on = false;
  EspNowProbe.away = true;
  Response_P(PSTR("{\"%s\":{\"Channel\":%u,\"Seconds\":%u,\"BeaconMs\":%u}}"), XdrvMailbox.command, channel, seconds, beacon);
  EspNowProbe.away_paused = false;
  AddLog(LOG_LEVEL_INFO, PSTR("EPR: Away on channel %u for %u s, the WiFi pauses"), channel, seconds);
#else
  ResponseCmndChar_P(PSTR("needs USE_WIFI_STATION_CONTROL"));
#endif  // USE_WIFI_STATION_CONTROL
}

const char kEspNowProbeCommands[] PROGMEM = "|"
  "EspNowProbe|EspNowProbeSend|EspNowProbeListen|EspNowProbeNap|EspNowProbeAway";
void (* const kEspNowProbeCommand[])(void) PROGMEM = {
  &CmndEspNowProbe, &CmndEspNowProbeSend, &CmndEspNowProbeListen, &CmndEspNowProbeNap, &CmndEspNowProbeAway };

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv101(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_INIT:
      EspNowProbeStart();
      break;
    case FUNC_EVERY_100_MSECOND:
      EspNowProbeEvery100ms();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kEspNowProbeCommands, kEspNowProbeCommand);
      break;
  }
  return result;
}

#endif  // USE_ESPNOW_MESH_PROBE
#endif  // USE_ESPNOW_MESH
