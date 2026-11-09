#include "SnowUSB.h"
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <string.h>

static int property(io_service_t entry, CFStringRef key) {
    CFTypeRef value = IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0);
    int number = -1;
    if (value) {
        if (CFGetTypeID(value) == CFNumberGetTypeID()) CFNumberGetValue(value, kCFNumberIntType, &number);
        CFRelease(value);
    }
    return number;
}

IOReturn SnowUSBOpen(SnowUSB *usb, const char **stage) {
    *usb = (SnowUSB){0};
    *stage = "Find Snow MIDI interface 3";
    io_iterator_t iterator = 0;
    IOReturn status = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOUSBHostInterface"), &iterator);
    if (status) return status;
    io_service_t match = 0;
    unsigned matches = 0;
    io_service_t entry;
    while ((entry = IOIteratorNext(iterator))) {
        io_registry_entry_t parent = 0;
        if (property(entry, CFSTR("bInterfaceNumber")) == 3 &&
            property(entry, CFSTR("bAlternateSetting")) == 0 &&
            property(entry, CFSTR("bInterfaceClass")) == 255 &&
            IORegistryEntryGetParentEntry(entry, kIOServicePlane, &parent) == kIOReturnSuccess) {
            if (property(parent, CFSTR("idVendor")) == 0x133e && property(parent, CFSTR("idProduct")) == 0x0815) {
                if (++matches == 1) { IOObjectRetain(entry); match = entry; }
            }
            IOObjectRelease(parent);
        }
        IOObjectRelease(entry);
    }
    IOObjectRelease(iterator);
    if (matches != 1) {
        if (match) IOObjectRelease(match);
        return matches ? kIOReturnStillOpen : kIOReturnNotFound;
    }

    *stage = "Create IOKit interface client";
    IOCFPlugInInterface **plugin = NULL;
    SInt32 score = 0;
    status = IOCreatePlugInInterfaceForService(match, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
    IOObjectRelease(match);
    if (status || !plugin) return status ? status : kIOReturnNoResources;
    HRESULT result = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID942), (LPVOID *)&usb->interface);
    IODestroyPlugInInterface(plugin);
    if (result || !usb->interface) { SnowUSBClose(usb); return kIOReturnUnsupported; }

    *stage = "Open interface without seizing it";
    IOUSBInterfaceInterface **iface = usb->interface;
    status = (*iface)->USBInterfaceOpen(iface);
    if (status) { SnowUSBClose(usb); return status; }
    usb->open = true;
    *stage = "Check MIDI pipe directions and packet sizes";
    UInt8 count = 0;
    status = (*iface)->GetNumEndpoints(iface, &count);
    if (!status && count != 2) status = kIOReturnUnsupported;
    for (UInt8 pipe = 1; !status && pipe <= count; pipe++) {
        UInt8 direction, number, type, interval;
        UInt16 size;
        status = (*iface)->GetPipeProperties(iface, pipe, &direction, &number, &type, &size, &interval);
        if (status) break;
        if (type != kUSBBulk || size < 4 || size > 64 || size % 4) {
            status = kIOReturnUnsupported;
        } else if (direction == kUSBIn && !usb->inputPipe) {
            usb->inputPipe = pipe;
            usb->inputSize = size;
        } else if (direction == kUSBOut && !usb->outputPipe) {
            usb->outputPipe = pipe;
            usb->outputSize = size;
        } else {
            status = kIOReturnUnsupported;
        }
    }
    if (!status && (!usb->inputPipe || !usb->outputPipe)) status = kIOReturnNotFound;
    if (status) SnowUSBClose(usb);
    return status;
}

void SnowUSBClose(SnowUSB *usb) {
    if (usb->interface) {
        if (usb->open) (*usb->interface)->USBInterfaceClose(usb->interface);
        (*usb->interface)->Release(usb->interface);
    }
    *usb = (SnowUSB){0};
}

static IOReturn writePipe(SnowUSB *usb, uint8_t *packet, UInt32 length) {
    return (*usb->interface)->WritePipeTO(usb->interface, usb->outputPipe, packet, length, 500, 500);
}

IOReturn SnowUSBStart(SnowUSB *usb) {
    uint8_t startup[] = {0x4e, 0x73, 0x52, 0x01};
    return writePipe(usb, startup, sizeof(startup));
}

size_t SnowUSBEncodeSysEx(const uint8_t *message, size_t length, uint8_t *events, size_t capacity) {
    if (length < 2 || message[0] != 0xf0 || message[length - 1] != 0xf7 ||
        (length / 3 + (length % 3 != 0)) > capacity / 4) return 0;
    for (size_t i = 1; i < length - 1; i++) if (message[i] >= 0x80) return 0;
    size_t count = 0;
    for (size_t offset = 0; offset < length; offset += 3, count += 4) {
        size_t remaining = length - offset;
        size_t payload = remaining > 3 ? 3 : remaining;
        // Cable 1 is Plugin I/O. CIN 4 continues SysEx. CIN 5–7 terminate it.
        events[count] = 0x10 | (remaining > 3 ? 4 : 4 + payload);
        memset(events + count + 1, 0, 3);
        memcpy(events + count + 1, message + offset, payload);
    }
    return count;
}

size_t SnowUSBDecodePluginEvents(const uint8_t *events, size_t length, uint8_t *bytes) {
    static const uint8_t payloadSizes[16] = {0,0,2,3,3,1,2,3,3,3,3,3,2,2,3,1};
    size_t count = 0;
    for (size_t i = 0; i + 4 <= length; i += 4) {
        if (events[i] >> 4 != 1) continue;
        size_t payload = payloadSizes[events[i] & 15];
        memcpy(bytes + count, events + i + 1, payload);
        count += payload;
    }
    return count;
}

IOReturn SnowUSBWriteSysEx(SnowUSB *usb, const uint8_t *message, size_t length) {
    uint8_t events[704];
    size_t used = SnowUSBEncodeSysEx(message, length, events, sizeof(events));
    if (!used) return kIOReturnBadArgument;
    for (size_t offset = 0; offset < used; offset += usb->outputSize) {
        uint8_t packet[64] = {0};
        size_t left = used - offset;
        memcpy(packet, events + offset, left < usb->outputSize ? left : usb->outputSize);
        IOReturn status = writePipe(usb, packet, usb->outputSize);
        if (status) return status;
    }
    return kIOReturnSuccess;
}
