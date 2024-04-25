#include "MotorControl.h"

int stepPins[] = { 2, 3, 4, 5 };
MotorControl motor(stepPins);

unsigned long lastStepTime;                                                     // Timestamp of the last step
unsigned long stepTime = 0;                                                     // Timestamp for last step print

static const int stepsPerRevolution = 2048;                                     // Number of steps per full revolution
static const int stepLimit = 2500;                                              // Step count limit
static const int botStepLimit = 0;                                              // bot Step count limit

void calibrate() {
  motor.activateMotor(true);                                                    // Start motor in clockwise direction

  while (motor.isMotorActive() && motor.currentStep < 3000) {                   // Move 3000 steps clockwise
    motor.stepMotor();
    delay(2);
    motor.lastPosition = 1500;
    stepPrint();
  }

  motor.deactivateMotor();                                                      // Stop briefly before reversing direction
  delay(500);                                                                   // Wait for the motor to completely stop

  motor.activateMotor(false);                                                   // Re-activate motor in counterclockwise direction

  while (motor.isMotorActive() && motor.currentStep > 1500) {                   // Move 1500 steps counterclockwise
    motor.stepMotor();
    delay(2);
    stepPrint();
  }

  motor.currentStep = 1250;                                                     // Reset current step for future operations
  motor.deactivateMotor();                                                      // Calibration complete, stop the motor
  stepPrint();
}

float calculateStep() {
  unsigned long currentTime = millis();
  float elapsedMillis = currentTime - lastStepTime;

  if (elapsedMillis > 0) {
    float stepsPerMinute = (60.0 * 1000.0) / elapsedMillis;
    return (stepsPerMinute / stepsPerRevolution);
  }

  return 0.0;
}

void stepPrint() {
  float step = calculateStep();
  if (millis() - stepTime >= 100) {                                             // Check if 1 second has passed since the last step print
    Serial.print("   Step: ");
    Serial.println(motor.currentStep);
    stepTime = millis();                                                        // Update last step print time
  }
}

void processSerialCommand() {
  if (Serial.available() > 0) {
    String command = Serial.readStringUntil('\n');
    command.trim();
    if (command == "START1") {
      motor.activateMotor(false);                                               // Counter-clockwise
      lastStepTime = millis();
      stepTime = millis();
    } else if (command == "START2") {
      motor.activateMotor(true);                                                // Clockwise
      lastStepTime = millis();
      stepTime = millis();
    } else if (command == "STOP") {
      motor.deactivateMotor();
    }
    else if (command == "CALI") {
      calibrate();                                                              // Perform calibration sequence: 3000 steps clockwise, then 1500 steps counterclockwise
    }
  }
}

void setup() {
  Serial.begin(9600);
  calibrate();
}

void loop() {
  processSerialCommand();

  if (motor.isMotorActive()) {
    motor.stepMotor();

    if (motor.currentStep >= stepLimit) {                                       // Step limit reached, deactivate motor
      motor.deactivateMotor();
      motor.currentStep = 2500;
      Serial.println("Motor stopped due to step limit reached.");
    }
    if (motor.currentStep <= botStepLimit) {                                    // Step limit reached, deactivate motor
      motor.deactivateMotor();
      motor.currentStep = 0;
      Serial.println("Motor stopped due to bottom step limit reached.");
    }
    lastStepTime = millis();                                                    // Update last step time
    delay(2);                                                                   // Delay between steps
    stepPrint();
  } else {
    delay(100);                                                                 // Wait for serial commands
  }
}