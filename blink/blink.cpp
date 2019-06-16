#include <Arduino.h>

#include "segger/SEGGER_RTT.h"

void setup() {
    SEGGER_RTT_WriteString(0, "\n\n");
    SEGGER_RTT_WriteString(0, "Hello!\n");

    while (true) {
        delay(1000);
        SEGGER_RTT_WriteString(0, "PING\n");
    }
}

void loop() {

}
