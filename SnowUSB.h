// Direct transport for the Snow's vendor-specific MIDI interface.
#pragma once
#include <IOKit/usb/IOUSBLib.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    IOUSBInterfaceInterface **interface;
    UInt8 inputPipe;
    UInt8 outputPipe;
    UInt16 inputSize;
    UInt16 outputSize;
    Boolean open;
} SnowUSB;

IOReturn SnowUSBOpen(SnowUSB *usb, const char **stage);
void SnowUSBClose(SnowUSB *usb);
IOReturn SnowUSBStart(SnowUSB *usb);
IOReturn SnowUSBWriteSysEx(SnowUSB *usb, const uint8_t *message, size_t length);
size_t SnowUSBEncodeSysEx(const uint8_t *message, size_t length, uint8_t *events, size_t capacity);
size_t SnowUSBDecodePluginEvents(const uint8_t *events, size_t length, uint8_t *bytes);
