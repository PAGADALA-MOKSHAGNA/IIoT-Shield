#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <LiquidCrystal_I2C.h>
#include <Wire.h>
#include <HTTPClient.h>
#include "cram.h"

/* ---------------- LCD ---------------- */
LiquidCrystal_I2C lcd(0x27, 16, 2);

/* ---------------- WiFi ---------------- */
const char* WIFI_SSID = "Janardhana Rao";
const char* WIFI_PASS = "Madhavi#888";

/* ---------------- Web Auth ---------------- */
const char* http_user = "Mokshagna";
const char* http_pass = "mokshagna@3";

/* ---------------- Node A ---------------- */
const char *NODE_A_IP = "192.168.31.242"; // UPDATE IF NEEDED

/* ---------------- Sensors ---------------- */
const int gasPin  = 35;
const int tempPin = 34;
const int TrigPin = 26;
const int EchoPin = 27;

/* ---------------- Variables ---------------- */
int   gasADC = 0;
float temperatureC = 0.0;
float distanceCm = -1;

/* ---------------- Web Server ---------------- */
WebServer server(80);

/* ---------------- Security State ---------------- */
bool lastAuthStatusB = false;
String lastAuthMessageB = "Idle";

/* ---------------- Replay Protection ---------------- */
String nonceHistoryB[10];
int nonceIndexB = 0;

/* ================================================= */
/* ============ REPLAY DETECTION ===================== */
/* ================================================= */

bool isNonceReusedB(String nonceStr) {
  for (int i = 0; i < 10; i++) {
    if (nonceHistoryB[i] == nonceStr) {
      return true;
    }
  }

  nonceHistoryB[nonceIndexB] = nonceStr;
  nonceIndexB = (nonceIndexB + 1) % 10;

  return false;
}

/* ================================================= */
/* ================= HTML =========================== */
/* ================================================= */

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<title>Node B</title>
<script>
setInterval(() => {
  fetch("/data")
    .then(res => res.json())
    .then(d => {
      document.getElementById("gas").innerText  = d.gas;
      document.getElementById("temp").innerText = d.temp;
      document.getElementById("dist").innerText = d.dist;
    });
}, 1000);

function triggerAuthB() {
  fetch('/trigger_auth')
    .then(res => res.json())
    .then(d => {
      document.getElementById('auth_status_b').innerText = d.status;
    });
}
</script>
</head>
<body>
<h2>Node B Dashboard</h2>
<p>Gas: <span id="gas">--</span></p>
<p>Temp: <span id="temp">--</span> °C</p>
<p>Distance: <span id="dist">--</span> cm</p>

<button onclick="triggerAuthB()">Authenticate Node A</button>
<p>Status: <span id="auth_status_b"></span></p>

</body>
</html>
)rawliteral";

/* ================================================= */
/* ================= HANDLERS ======================= */
/* ================================================= */

void handleRoot() {
  if (!server.authenticate(http_user, http_pass)) {
    return server.requestAuthentication();
  }
  server.send(200, "text/html", index_html);
}

/* ---------------- Sensor API ---------------- */
void handleData() {
  if (!server.authenticate(http_user, http_pass)) {
    return server.requestAuthentication();
  }

  String json = "{";
  json += "\"gas\":" + String(gasADC) + ",";
  json += "\"temp\":" + String(temperatureC,1) + ",";
  json += "\"dist\":" + String(distanceCm,1);
  json += "}";

  server.send(200, "application/json", json);
}

/* ---------------- STATUS API ---------------- */
void handleStatusB() {
  if (!server.authenticate(http_user, http_pass)) {
    return server.requestAuthentication();
  }

  String json = "{";
  json += "\"node\":\"B\",";
  json += "\"status\":\"ONLINE\",";
  json += "\"auth\":\"" + lastAuthMessageB + "\",";
  json += "\"gas\":" + String(gasADC) + ",";
  json += "\"temp\":" + String(temperatureC,1) + ",";
  json += "\"dist\":" + String(distanceCm,1);
  json += "}";

  server.send(200, "application/json", json);
}

/* ================================================= */
/* ============ CRAM RESPONDER ======================= */
/* ================================================= */

void handleCRAMChallenge() {

  if (!server.authenticate(http_user, http_pass)) {
    return server.requestAuthentication();
  }

  if (!server.hasArg("nonce")) {
    server.send(400, "text/plain", "Missing nonce");
    return;
  }

  String nonceStr = server.arg("nonce");

  // 🔥 Replay Detection
  if (isNonceReusedB(nonceStr)) {
    Serial.println("⚠️ REPLAY ATTACK DETECTED");
    lastAuthStatusB = false;
    lastAuthMessageB = "Replay Detected";
    server.send(403, "text/plain", "Replay Attack");
    return;
  }

  uint8_t nonce[8];
  for (int i = 0; i < 8; i++) {
    sscanf(nonceStr.substring(i*2, i*2+2).c_str(), "%hhx", &nonce[i]);
  }

  uint8_t hmac[32];
  generate_hmac(nonce, 8, hmac);

  lastAuthStatusB = true;
  lastAuthMessageB = "Responded";

  String response = "";
  for (int i = 0; i < 32; i++) {
    char buf[3];
    sprintf(buf, "%02X", hmac[i]);
    response += buf;
  }

  server.send(200, "text/plain", response);
}

/* ================================================= */
/* ============ CRAM INITIATOR ======================= */
/* ================================================= */

bool performCRAMHandshakeFromB() {

  uint8_t nonce[8];
  uint8_t received_hmac[32];

  generate_nonce(nonce, 8);

  String nonceStr = "";
  for (int i = 0; i < 8; i++) {
    char buf[3];
    sprintf(buf, "%02X", nonce[i]);
    nonceStr += buf;
  }

  HTTPClient http;
  String url = "http://" + String(NODE_A_IP) + "/cram?nonce=" + nonceStr;

  http.begin(url);
  http.setAuthorization("Mokshagna", "MLG333");

  int httpCode = http.GET();

  if (httpCode == 200) {
    String response = http.getString();

    for (int i = 0; i < 32; i++) {
      sscanf(response.substring(i*2, i*2+2).c_str(), "%hhx", &received_hmac[i]);
    }

    if (verify_hmac(nonce, 8, received_hmac)) {
      lastAuthStatusB = true;
      lastAuthMessageB = "Auth Success";
      http.end();
      return true;
    }
  }

  lastAuthStatusB = false;
  lastAuthMessageB = "Auth Failed";

  http.end();
  return false;
}

/* ---------------- Trigger ---------------- */
void handleTriggerFromB() {

  if (!server.authenticate(http_user, http_pass)) {
    return server.requestAuthentication();
  }

  bool success = performCRAMHandshakeFromB();

  String response = "{";
  response += "\"status\":\"";
  response += success ? "SUCCESS" : "FAILED";
  response += "\"}";

  server.send(200, "application/json", response);
}

/* ================================================= */
/* ================= SETUP ========================== */
/* ================================================= */

void setup() {
  Serial.begin(115200);
  cram_init();

  pinMode(gasPin, INPUT);
  pinMode(tempPin, INPUT);
  pinMode(TrigPin, OUTPUT);
  pinMode(EchoPin, INPUT);

  Wire.begin();
  lcd.init();
  lcd.backlight();

  lcd.print("Node B Starting");

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nConnected!");
  Serial.println(WiFi.localIP());

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("WiFi Connected");

  lcd.setCursor(0, 1);
  lcd.print(WiFi.localIP().toString());

  delay(3000);
  lcd.clear();

  server.on("/", handleRoot);
  server.on("/data", handleData);
  server.on("/status", handleStatusB);
  server.on("/cram", handleCRAMChallenge);
  server.on("/trigger_auth", handleTriggerFromB);

  server.begin();
}

/* ================================================= */
/* ================= LOOP =========================== */
/* ================================================= */

void loop() {

  server.handleClient();

  gasADC = analogRead(gasPin);

  int tempADC = analogRead(tempPin);
  temperatureC = ((tempADC / 4095.0) * 3.3) * 100.0;

  digitalWrite(TrigPin, LOW);
  delayMicroseconds(2);
  digitalWrite(TrigPin, HIGH);
  delayMicroseconds(10);
  digitalWrite(TrigPin, LOW);

  long d = pulseIn(EchoPin, HIGH, 30000);
  distanceCm = (d == 0) ? -1 : (d * 0.034 / 2);

  lcd.clear();

  /* -------- Row 1: Gas + Distance -------- */
  lcd.setCursor(0, 0);
  lcd.print("Gas:");
  lcd.print(gasADC);

  lcd.setCursor(10, 0);
  if (distanceCm < 0) {
    lcd.print("---");
  } else {
    lcd.print((int)distanceCm);
  }
  lcd.print("cm");

  /* -------- Row 2: Temperature -------- */
  lcd.setCursor(0, 1);
  lcd.print("Temp:");
  lcd.print(temperatureC, 1);
  lcd.print((char)223); // degree symbol
  lcd.print("C");

  delay(1000);
}