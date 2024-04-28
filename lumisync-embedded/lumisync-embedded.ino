#include "MotorControl.h"

static const int stepLimit = 2500;                                              // Step count limit
static const int botStepLimit = 0;                                              // bot Step count limit

int stepPins[] = { 2, 3, 4, 5 };
MotorControl motor(stepPins, botStepLimit, stepLimit);

void calibrateSync(int defaultStep = 1250) {
  motor.moveToSync(stepLimit);
  motor.setCurrentStep(stepLimit);
  delay(500);                                                                   // Wait for the motor to completely stop
  motor.moveToSync(defaultStep);
  motor.setCurrentStep(defaultStep);
}

void onStep(int currentStep) {
  Serial.println("{\"currentStep\": " + String(currentStep) + "}");
}

void setup() {
  Serial.begin(9600);
  calibrateSync();
  motor.setStepCallback(onStep);
}

void loop() {
  if (Serial.available() > 0) {
    String command = Serial.readStringUntil('\n');
    command.trim();
    float targetAngle;

    if (command.startsWith("SET ")) {
      targetAngle = constrain(command.substring(4).toFloat(), -1.0, 1.0);
      motor.moveTo((int)((targetAngle + 1.0) / 2.0 * stepLimit));
    } else if (command == "STOP") {
      motor.deactivateMotor();
    }
    else if (command == "CALI") {
      calibrateSync();                                                          // Perform calibration sequence: 3000 steps clockwise, then 1500 steps counterclockwise
    }
  }

  motor.update();
}