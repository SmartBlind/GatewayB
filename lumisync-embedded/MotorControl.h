#ifndef MotorControl_h
#define MotorControl_h

#include "Arduino.h"

typedef void (*MotorStepCallback)(int currentStep);

class MotorControl {
  public:
    MotorControl(int* pins, int minStep, int maxStep);
    // Updater for execute at main thread
    void update();

    // Activate the motor with specified direction
    void activateMotor(bool clockwise);
    // Deactivate the motor
    void deactivateMotor();
    // Perform one step in the specified direction
    void stepMotor();

    // Move to target step on coroutine
    void moveTo(int targetStep);
    // Move to target step on main thread
    void moveToSync(int targetStep);

    void setStepCallback(MotorStepCallback callback) { m_stepCallback = callback; }

    int getCurrentStep() const { return m_currentStep; }
    void setCurrentStep(int currentStep) { m_currentStep = currentStep; }
    int getLastPosition() const { return m_lastPosition; }
    void setLastPosition(int lastPosition) { m_lastPosition = lastPosition; }

    bool isClockwise() const { return m_clockwise; }
    bool isMotorActive() const { return m_motorActive; }

  private:
    // Define stepping sequence count
    static const int stepCount = 4;
    // Define motor stepping sequences for full step
    static const int fullSteps[stepCount][4];
    // Define time between steps in milliseconds
    const unsigned long stepDelay = 2;

    // Motor driver input pins
    int* m_stepPins;

    // Step count min, max limit
    int m_minStep, m_maxStep;

    MotorStepCallback m_stepCallback = nullptr;

    // Target step position for movements
    int m_targetStep = 0;
    // Current step position
    int m_currentStep = 0;

    // Timestamp of the last step
    unsigned long m_lastStepTime = 0;
    // Last known motor position
    int m_lastPosition = 0;

    // Motor rotation direction
    bool m_clockwise = true;
    // Motor activation status
    bool m_motorActive = false;
};

#endif