#include "MotorControl.h"

const int MotorControl::fullSteps[MotorControl::stepCount][4] = {
  { HIGH, HIGH, LOW, LOW },
  { LOW, HIGH, HIGH, LOW },
  { LOW, LOW, HIGH, HIGH },
  { HIGH, LOW, LOW, HIGH }
};

MotorControl::MotorControl(int* pins, int minStep, int maxStep)
  : m_stepPins(pins), m_minStep(minStep), m_maxStep(maxStep) {}

void MotorControl::update() {
  unsigned long currentTime = millis();
  if (m_motorActive) {
    if ((m_clockwise  && m_currentStep >= m_targetStep) ||
        (!m_clockwise && m_currentStep <= m_targetStep)) {
      deactivateMotor();
    } else {
      if (currentTime - m_lastStepTime >= stepDelay) {
        stepMotor();
        m_lastStepTime = currentTime;
      }
    }
  }
}

void MotorControl::activateMotor(bool directionClockwise) {
  for (int i = 0; i < 4; i++) {
    pinMode(m_stepPins[i], OUTPUT);
    digitalWrite(m_stepPins[i], LOW);
  }
  m_clockwise = directionClockwise;
  m_motorActive = true;
  m_lastPosition = m_currentStep;
}

void MotorControl::deactivateMotor() {
  for (int i = 0; i < 4; i++) {
    pinMode(m_stepPins[i], INPUT);
  }
  m_motorActive = false;
  m_lastPosition = m_currentStep;
}

void MotorControl::stepMotor() {
  // Calculate step index for motion
  int stepIndex = m_clockwise ? m_currentStep % stepCount : (stepCount - 1) - (m_currentStep % stepCount);

  // Output the step sequence to the motor driver
  for (int i = 0; i < 4; i++) {
    digitalWrite(m_stepPins[i], fullSteps[stepIndex][i]);
  }

  // Adjust the current step based on the direction
  m_currentStep += m_clockwise ? 1 : -1;
}

void MotorControl::moveTo(int targetStep) {
  m_targetStep = constrain(targetStep, m_minStep, m_maxStep);
  if (m_currentStep != m_targetStep) {
    activateMotor(m_targetStep > m_currentStep);
  }
}

void MotorControl::moveToSync(int targetStep) {
  m_targetStep = constrain(targetStep, m_minStep, m_maxStep);

  if (m_currentStep == m_targetStep) return;

  activateMotor(m_targetStep > m_currentStep);

  while (m_motorActive && m_currentStep != m_targetStep) {
    stepMotor();
    delay(stepDelay);
    if (m_stepCallback != nullptr) {
      m_stepCallback(m_currentStep);
    }
  }

  deactivateMotor();
}