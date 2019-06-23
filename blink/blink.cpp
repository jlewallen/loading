#include <Arduino.h>
#include <SEGGER_RTT.h>
#include <loading.h>

void setup() {
    delay(500);

    SEGGER_RTT_WriteString(0, "\n\n");
    SEGGER_RTT_WriteString(0, "Hello!\n");
    SEGGER_RTT_printf(0, "Memory: %lu\n", fkb_launch_info.memory_used);

    while (true) {
        delay(1000);
        SEGGER_RTT_WriteString(0, "PING\n");
    }
}

void loop() {

}
