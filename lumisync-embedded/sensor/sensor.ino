#include <Ethernet.h>
#include <MQTT.h>

// Configuration
byte mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
byte ip[] = {192, 168, 1, 10};

EthernetClient net;
MQTTClient client;

const int ldrPin = A0;                                                          // LDR should be connected to an analog pin
char sensorID[24];                                                              // The unique sensor client ID

void setup() {
  pinMode(ldrPin, INPUT);
  Serial.begin(9600);

  Ethernet.begin(mac, ip);
  client.begin("127.0.0.1", 1883, net);
  client.onMessage(messageReceived);

  snprintf(sensorID, sizeof(sensorID), "SENSOR-%02X%02X%02X%02X",
           mac[2], mac[3], mac[4], mac[5]);

  connect();
}

void loop() {
  client.loop();

  if (!client.connected()) {
    connect();
  }

  static unsigned long lastMillis = 0;
  if (millis() - lastMillis > 1000) {
    lastMillis = millis();
    int ldrValue = analogRead(ldrPin);                                          // Read the LDR analog value
    float lux = map(ldrValue, 0, 1023, 0, 1000);

    Serial.print("Lux=");
    Serial.println(lux);

    char jsonBuffer[100];
    sprintf(jsonBuffer, "{\"id\":\"%s\", \"lght\":%d}", sensorID, lux);

    client.publish("/internal/sensor", jsonBuffer);
  }
}

void connect() {
  Serial.print("Connecting to MQTT...");
  while (!client.connect("arduinoClient")) {
    Serial.print(".");
    delay(1000);
  }
  Serial.println("\nConnected!");
  client.subscribe("/internal/ldrSensor");
}

void messageReceived(String &topic, String &payload) {
  Serial.println("Incoming: " + topic + " - " + payload);
}