#include <Arduino.h>
#include <SEGGER_RTT.h>
#include <loading.h>

#if defined(FKB_ENABLE_HEADER__)
extern "C" {

}
#endif

void setup() {
    delay(500);

    SEGGER_RTT_Init();

    SEGGER_RTT_WriteString(0, "\n\n");
    SEGGER_RTT_WriteString(0, "Hello!\n");

    while (true) {
        delay(1000);
        SEGGER_RTT_WriteString(0, "PING\n");
    }
}

void loop() {

}
