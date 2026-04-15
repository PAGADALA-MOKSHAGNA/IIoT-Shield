#include <WiFi.h>
#include "esp_wifi.h"

/* ================================================= */
/* ============== CONFIGURATION ===================== */
/* ================================================= */

// Replace with your actual Node A & Node B MAC addresses
uint8_t knownNodeA[6] = {0x00, 0x4B, 0x12, 0xEE, 0x5E, 0x44};
uint8_t knownNodeB[6] = {0x78, 0x42, 0x1C, 0x6D, 0x61, 0xF4};

/* ---------------- Flood Detection ---------------- */
unsigned long lastPacketTime = 0;
int packetCount = 0;

/* ---------------- Replay Detection ---------------- */
#define HISTORY_SIZE 15
String packetHistory[HISTORY_SIZE];
int historyIndex = 0;

/* ================================================= */
/* ============== HELPER FUNCTIONS ================== */
/* ================================================= */

String macToString(uint8_t *mac) {
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2],
          mac[3], mac[4], mac[5]);
  return String(buf);
}

bool isKnownDevice(uint8_t *mac) {
  if (memcmp(mac, knownNodeA, 6) == 0) return true;
  if (memcmp(mac, knownNodeB, 6) == 0) return true;
  return false;
}

/* ---------------- JSON Logger ---------------- */
void logEvent(String type, String message, String mac) {

  String json = "{";
  json += "\"type\":\"" + type + "\",";
  json += "\"message\":\"" + message + "\",";
  json += "\"mac\":\"" + mac + "\",";
  json += "\"time\":" + String(millis());
  json += "}";

  Serial.println(json);
}

/* ---------------- Replay Detection ---------------- */
bool isReplay(String signature) {
  for (int i = 0; i < HISTORY_SIZE; i++) {
    if (packetHistory[i] == signature) {
      return true;
    }
  }

  packetHistory[historyIndex] = signature;
  historyIndex = (historyIndex + 1) % HISTORY_SIZE;

  return false;
}

/* ================================================= */
/* ================= IDS CALLBACK =================== */
/* ================================================= */

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t *payload = pkt->payload;

  uint8_t *src_mac = payload + 10;

  String macStr = macToString(src_mac);

  /* ---------------- Rogue Detection ---------------- */
  if (!isKnownDevice(src_mac)) {
    return;
  }

  /* ---------------- Flood Detection ---------------- */
  unsigned long now = millis();

  if (now - lastPacketTime < 200) {
    packetCount++;
  } else {
    packetCount = 0;
  }

  lastPacketTime = now;

  if (packetCount > 15) {
    logEvent("FLOOD", "High Traffic Detected", macStr);
    return;
  }

  /* ---------------- Replay Detection ---------------- */
  String signature = macStr + "_" + String(pkt->rx_ctrl.sig_len);

  if (isReplay(signature)) {
    logEvent("REPLAY", "Repeated Packet Pattern", macStr);
    return;
  }

  /* ---------------- Normal Traffic ---------------- */
  logEvent("NORMAL", "Valid Packet", macStr);
}

/* ================================================= */
/* ==================== SETUP ======================= */
/* ================================================= */

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("{\"type\":\"SYSTEM\",\"message\":\"IDS Node Started\"}");

  WiFi.mode(WIFI_STA);

  // Enable promiscuous mode
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(sniffer);

  Serial.println("{\"type\":\"SYSTEM\",\"message\":\"Promiscuous Mode Enabled\"}");
}

/* ================================================= */
/* ===================== LOOP ======================= */
/* ================================================= */

void loop() {
  delay(100);
}