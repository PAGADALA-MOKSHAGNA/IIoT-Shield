#include <WiFi.h>
#include <WebServer.h>
#include "esp_wifi.h"

/* ================================================= */
/* ============== CONFIGURATION ===================== */
/* ================================================= */

const char *WIFI_SSID = "Janardhana Rao";
const char *WIFI_PASS = "Madhavi#888";

#define HISTORY_SIZE 15
#define IDS_LOG_LIMIT 20

const unsigned long FLOOD_WINDOW_MS = 200;
const int FLOOD_THRESHOLD = 15;
const unsigned long REPLAY_WINDOW_MS = 1200;
const unsigned long ALERT_COOLDOWN_MS = 1500;
const unsigned long NORMAL_LOG_INTERVAL_MS = 1000;
const unsigned long WIFI_RETRY_MS = 10000;
const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;

struct ReplayEntry
{
  String signature;
  unsigned long seenAt;
};

struct EventRecord
{
  String type;
  String message;
  String node;
  String mac;
  String peer;
  String direction;
  unsigned long time;
};

struct NodeTracker
{
  const char *name;
  uint8_t mac[6];
  unsigned long lastPacketTime;
  int packetCount;
  ReplayEntry history[HISTORY_SIZE];
  int historyIndex;
  unsigned long lastFloodLog;
  unsigned long lastReplayLog;
  unsigned long lastNormalLog;
};

NodeTracker nodeA = {"Node A", {0x00, 0x4B, 0x12, 0xEE, 0x5E, 0x44}};
NodeTracker nodeB = {"Node B", {0x78, 0x42, 0x1C, 0x6D, 0x61, 0xF4}};

WebServer server(80);

EventRecord latestEvent = {"SYSTEM", "Booting", "-", "-", "-", "-", 0};
EventRecord eventLog[IDS_LOG_LIMIT];
int eventLogIndex = 0;
int eventLogCount = 0;
unsigned long lastWifiRetryAt = 0;

/* ================================================= */
/* ============== HELPER FUNCTIONS ================== */
/* ================================================= */

String macToString(const uint8_t *mac)
{
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2],
          mac[3], mac[4], mac[5]);
  return String(buf);
}

bool macEquals(const uint8_t *lhs, const uint8_t *rhs)
{
  return memcmp(lhs, rhs, 6) == 0;
}

NodeTracker *getKnownNode(const uint8_t *mac)
{
  if (macEquals(mac, nodeA.mac))
  {
    return &nodeA;
  }

  if (macEquals(mac, nodeB.mac))
  {
    return &nodeB;
  }

  return nullptr;
}

bool readyToLog(unsigned long &lastLoggedAt, unsigned long intervalMs, unsigned long now)
{
  if (lastLoggedAt != 0 && (now - lastLoggedAt) < intervalMs)
  {
    return false;
  }

  lastLoggedAt = now;
  return true;
}

String escapeJson(const String &value)
{
  String escaped = value;
  escaped.replace("\\", "\\\\");
  escaped.replace("\"", "\\\"");
  return escaped;
}

String eventToJson(const EventRecord &event)
{
  String json = "{";
  json += "\"type\":\"" + escapeJson(event.type) + "\",";
  json += "\"message\":\"" + escapeJson(event.message) + "\",";
  json += "\"node\":\"" + escapeJson(event.node) + "\",";
  json += "\"mac\":\"" + escapeJson(event.mac) + "\",";
  json += "\"peer\":\"" + escapeJson(event.peer) + "\",";
  json += "\"direction\":\"" + escapeJson(event.direction) + "\",";
  json += "\"time\":" + String(event.time);
  json += "}";
  return json;
}

void rememberEvent(const EventRecord &event)
{
  latestEvent = event;
  eventLog[eventLogIndex] = event;
  eventLogIndex = (eventLogIndex + 1) % IDS_LOG_LIMIT;

  if (eventLogCount < IDS_LOG_LIMIT)
  {
    eventLogCount++;
  }
}

void publishEvent(const String &type,
                  const String &message,
                  const String &nodeName,
                  const String &nodeMac,
                  const String &peerMac,
                  const String &direction)
{
  EventRecord event = {
      type,
      message,
      nodeName,
      nodeMac,
      peerMac,
      direction,
      millis()};

  rememberEvent(event);
  Serial.println(eventToJson(event));
}

bool isReplay(NodeTracker *tracker, const String &signature, unsigned long now)
{
  for (int i = 0; i < HISTORY_SIZE; i++)
  {
    if (tracker->history[i].signature == signature)
    {
      bool replay = (now - tracker->history[i].seenAt) <= REPLAY_WINDOW_MS;
      tracker->history[i].seenAt = now;
      return replay;
    }
  }

  tracker->history[tracker->historyIndex].signature = signature;
  tracker->history[tracker->historyIndex].seenAt = now;
  tracker->historyIndex = (tracker->historyIndex + 1) % HISTORY_SIZE;
  return false;
}

/* ================================================= */
/* ================= HTTP HANDLERS ================== */
/* ================================================= */

void handleRoot()
{
  String html = "<!doctype html><html><head><meta charset=\"utf-8\"><title>ESP32 IDS</title></head><body>";
  html += "<h2>ESP32 Promiscuous IDS</h2>";
  html += "<p><strong>IP:</strong> " + WiFi.localIP().toString() + "</p>";
  html += "<p><strong>WiFi:</strong> " + String(WiFi.status() == WL_CONNECTED ? "CONNECTED" : "DISCONNECTED") + "</p>";
  html += "<p><strong>Latest Event:</strong> " + latestEvent.type + " - " + latestEvent.message + "</p>";
  html += "<p>JSON endpoints: <code>/status</code>, <code>/latest</code>, <code>/logs</code></p>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleStatus()
{
  String json = "{";
  json += "\"status\":\"ONLINE\",";
  json += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
  json += "\"wifi\":\"" + String(WiFi.status() == WL_CONNECTED ? "CONNECTED" : "DISCONNECTED") + "\",";
  json += "\"channel\":" + String(WiFi.channel()) + ",";
  json += "\"uptime_ms\":" + String(millis()) + ",";
  json += "\"sniffing\":true,";
  json += "\"latest\":" + eventToJson(latestEvent);
  json += "}";

  server.send(200, "application/json", json);
}

void handleLatest()
{
  server.send(200, "application/json", eventToJson(latestEvent));
}

void handleLogs()
{
  String json = "{\"logs\":[";
  int start = eventLogCount < IDS_LOG_LIMIT ? 0 : eventLogIndex;

  for (int i = 0; i < eventLogCount; i++)
  {
    int idx = (start + i) % IDS_LOG_LIMIT;
    if (i > 0)
    {
      json += ",";
    }
    json += eventToJson(eventLog[idx]);
  }

  json += "]}";
  server.send(200, "application/json", json);
}

/* ================================================= */
/* ================= IDS CALLBACK =================== */
/* ================================================= */

void sniffer(void *buf, wifi_promiscuous_pkt_type_t type)
{
  if (type != WIFI_PKT_DATA)
  {
    return;
  }

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  if (pkt->rx_ctrl.sig_len < 24)
  {
    return;
  }

  uint8_t *payload = pkt->payload;
  const uint8_t *dst_mac = payload + 4;
  const uint8_t *src_mac = payload + 10;

  NodeTracker *tracker = getKnownNode(src_mac);
  const uint8_t *peerMac = dst_mac;
  String direction = "outbound";
  bool isInbound = false;

  if (tracker == nullptr)
  {
    tracker = getKnownNode(dst_mac);
    peerMac = src_mac;
    direction = "inbound";
    isInbound = true;
  }

  // Ignore unrelated devices so rogue traffic does not spam the dashboard or serial monitor.
  if (tracker == nullptr)
  {
    return;
  }

  unsigned long now = millis();
  String nodeMacStr = macToString(tracker->mac);
  String peerMacStr = macToString(peerMac);

  if ((now - tracker->lastPacketTime) < FLOOD_WINDOW_MS)
  {
    tracker->packetCount++;
  }
  else
  {
    tracker->packetCount = 1;
  }
  tracker->lastPacketTime = now;

  if (tracker->packetCount > FLOOD_THRESHOLD)
  {
    if (readyToLog(tracker->lastFloodLog, ALERT_COOLDOWN_MS, now))
    {
      publishEvent(
          "FLOOD",
          String(tracker->name) + " high traffic burst",
          tracker->name,
          nodeMacStr,
          peerMacStr,
          direction);
    }
    return;
  }

  if (isInbound)
  {
    String signature = peerMacStr + "_" + String(type) + "_" + String(pkt->rx_ctrl.sig_len);
    if (isReplay(tracker, signature, now))
    {
      if (readyToLog(tracker->lastReplayLog, ALERT_COOLDOWN_MS, now))
      {
        publishEvent(
            "REPLAY",
            String(tracker->name) + " repeated packet pattern",
            tracker->name,
            nodeMacStr,
            peerMacStr,
            direction);
      }
      return;
    }
  }

  if (readyToLog(tracker->lastNormalLog, NORMAL_LOG_INTERVAL_MS, now))
  {
    publishEvent(
        "NORMAL",
        String(tracker->name) + " traffic observed",
        tracker->name,
        nodeMacStr,
        peerMacStr,
        direction);
  }
}

/* ================================================= */
/* ================= WIFI HELPERS =================== */
/* ================================================= */

void connectToWiFi()
{
  if (WiFi.status() == WL_CONNECTED)
  {
    return;
  }

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  unsigned long startedAt = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - startedAt) < WIFI_CONNECT_TIMEOUT_MS)
  {
    delay(500);
    Serial.print(".");
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED)
  {
    publishEvent(
        "SYSTEM",
        "WiFi connected: " + WiFi.localIP().toString(),
        "-",
        WiFi.macAddress(),
        "-",
        "system");
  }
  else
  {
    publishEvent("ERROR", "WiFi connection failed", "-", "-", "-", "system");
  }
}

/* ================================================= */
/* ==================== SETUP ======================= */
/* ================================================= */

void setup()
{
  Serial.begin(115200);
  delay(1000);

  publishEvent("SYSTEM", "IDS Node Started", "-", "-", "-", "system");

  connectToWiFi();

  server.on("/", handleRoot);
  server.on("/status", handleStatus);
  server.on("/latest", handleLatest);
  server.on("/logs", handleLogs);
  server.begin();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(sniffer);

  publishEvent("SYSTEM", "Promiscuous Mode Enabled", "-", "-", "-", "system");
}

/* ================================================= */
/* ===================== LOOP ======================= */
/* ================================================= */

void loop()
{
  server.handleClient();

  if (WiFi.status() != WL_CONNECTED && (millis() - lastWifiRetryAt) >= WIFI_RETRY_MS)
  {
    lastWifiRetryAt = millis();
    connectToWiFi();
  }

  delay(10);
}
