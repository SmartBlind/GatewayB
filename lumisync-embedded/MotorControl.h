#ifndef MotorControl_h
#define MotorControl_h

#include "Arduino.h"

class MotorControl {
  public:
    MotorControl(int* pins);
    // Activate the motor with specified direction
    void activateMotor(bool clockwise);
    // Deactivate the motor
    void deactivateMotor();
    // Perform one step in the specified direction
    void stepMotor();

    bool isClockwise() const { return clockwise; }
    bool isMotorActive() const { return motorActive; }

    // Current step position
    int currentStep = 0;
    // Last known motor position
    int lastPosition = 0;

  private:
    // Motor driver input pins
    int* stepPins;
    // Define motor stepping sequences for full step
    static const int fullSteps[4][4];

    // Motor rotation direction
    bool clockwise = true;
    // Motor activation status
    bool motorActive = false;
};

#endif