#include "MotorControl.h"

const int MotorControl::fullSteps[4][4] = {
  { HIGH, HIGH, LOW, LOW },
  { LOW, HIGH, HIGH, LOW },
  { LOW, LOW, HIGH, HIGH },
  { HIGH, LOW, LOW, HIGH }
};

MotorControl::MotorControl(int* pins)
  : stepPins(pins) {}

void MotorControl::activateMotor(bool directionClockwise) {
  for (int i = 0; i < 4; i++) {
    pinMode(stepPins[i], OUTPUT);
    digitalWrite(stepPins[i], LOW);
  }
  clockwise = directionClockwise;
  motorActive = true;
  lastPosition = currentStep;
}

void MotorControl::deactivateMotor() {
  for (int i = 0; i < 4; i++) {
    pinMode(stepPins[i], INPUT);
  }
  motorActive = false;
  lastPosition = currentStep;
}

void MotorControl::stepMotor() {
  // Calculate the number of step sequences
  int stepCount = sizeof(fullSteps) / sizeof(fullSteps[0]);
  // Calculate step index for motion
  int stepIndex = clockwise ? currentStep % stepCount : (stepCount - 1) - (currentStep % stepCount);

  // Output the step sequence to the motor driver
  for (int i = 0; i < 4; i++) {
    digitalWrite(stepPins[i], fullSteps[stepIndex][i]);
  }

  // Adjust the current step based on the direction
  currentStep += clockwise ? 1 : -1;
}