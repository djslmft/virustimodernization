#import <Foundation/Foundation.h>
#import <CoreMIDI/CoreMIDI.h>
#include <pthread.h>
#import <CommonCrypto/CommonDigest.h>
#include "EditableParameters.h"
#include "SnowUSB.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// Whitelisted operations: identity, preset reads, and current-buffer edits and loads.
// No arbitrary-send option, stored-preset writes, program changes, notes or resets.
static const UInt8 requestBytes[] = {0xf0, 0x7e, 0x7f, 0x06, 0x01, 0xf7};
static const UInt8 presetRequestBytes[] = {0xf0,0x00,0x20,0x33,0x01,0x10,0x30,0x01,0x00,0xf7};
static const EditParameter *findParameter(const char *key) {
    for (unsigned i=0;i<editParameterCount;i++) if (!strcmp(editParameters[i].key,key)) return &editParameters[i];
    return NULL;
}
static NSString *packetDigest(NSData *packet) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(packet.bytes,(CC_LONG)packet.length,digest);
    NSMutableString *hex = [NSMutableString string];
    for (unsigned i=0;i<CC_SHA256_DIGEST_LENGTH;i++) [hex appendFormat:@"%02x",digest[i]];
    return hex;
}
static NSMutableArray<NSData *> *frames;
static NSMutableData *partial;
static NSUInteger receivedBytes, discardedFrames;
static NSUInteger captureByteLimit = 65536, captureFrameLimit = 16;
static NSUInteger byteHistogram[256], packetCount, smallestPacket, largestPacket;
static NSMutableData *prefix;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void resetCapture(void) {
    frames = [NSMutableArray array]; partial = [NSMutableData data];
    receivedBytes = 0; discardedFrames = 0;
    memset(byteHistogram, 0, sizeof(byteHistogram));
    prefix = [NSMutableData data]; packetCount = 0; smallestPacket = NSUIntegerMax; largestPacket = 0;
}

static NSDictionary *identity(NSData *frame) {
    const UInt8 *b = frame.bytes;
    NSUInteger n = frame.length;
    if (n < 15 || b[0] != 0xf0 || b[1] != 0x7e || b[3] != 6 || b[4] != 2 || b[n-1] != 0xf7) return nil;
    NSUInteger width = b[5] == 0 ? 3 : 1;
    if (n != 14 + width) return nil;
    for (NSUInteger i = 1; i < n-1; i++) if (b[i] > 0x7f) return nil;
    NSUInteger offset = 5 + width;
    NSMutableArray *manufacturer = [NSMutableArray array], *version = [NSMutableArray array];
    for (NSUInteger i = 0; i < width; i++) [manufacturer addObject:@(b[5+i])];
    for (NSUInteger i = 0; i < 4; i++) [version addObject:@(b[offset+4+i])];
    return @{ @"deviceID": @(b[2]), @"manufacturerBytes": manufacturer,
              @"family": @(b[offset] | b[offset+1] << 7),
              @"member": @(b[offset+2] | b[offset+3] << 7),
              @"versionBytes": version };
}

static NSDictionary *singlePreset(NSData *frame) {
    const UInt8 *b = frame.bytes; NSUInteger size = frame.length;
    if ((size != 267 && size != 524) || memcmp(b, "\xf0\x00\x20\x33\x01", 5) || b[6] != 0x10 || b[size-1] != 0xf7) return nil;
    BOOL valid = YES;
    for (NSUInteger i = 1; i < size-1; i++) if (b[i] > 127) valid = NO;
    unsigned sum = 0;
    for (NSUInteger i = 5; i <= 264; i++) sum += b[i];
    BOOL first = (sum & 127) == b[265], second = YES;
    if (size == 524) {
        sum = 0; for (NSUInteger i = 5; i <= 521; i++) sum += b[i];
        second = (sum & 127) == b[522];
    }
    NSString *patchName = [[NSString alloc] initWithBytes:b+249 length:10 encoding:NSASCIIStringEncoding];
    return @{ @"format": size == 524 ? @"VirusTI_Singledump" : @"VirusC_Singledump",
              @"bank": @(b[7]), @"program": @(b[8]), @"deviceID": @(b[5]), @"bytes": @(size),
              @"name": [patchName ?: @"" stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet],
              @"firstChecksumValid": @(first), @"secondChecksumValid": @(second),
              @"validated": @(valid && first && second), @"checksumCount": size == 524 ? @2 : @1 };
}

static NSData *factorySingleDump(NSData *frame) {
    if (frame.length != 524 || ![singlePreset(frame)[@"validated"] boolValue]) return nil;
    NSMutableData *dump = [frame mutableCopy];
    UInt8 *b = dump.mutableBytes;
    b[5] = presetRequestBytes[5];
    b[7] = 0;
    b[8] = 64;
    unsigned sum = 0;
    for (NSUInteger i = 5; i <= 264; i++) sum += b[i];
    b[265] = sum & 127;
    sum = 0;
    for (NSUInteger i = 5; i <= 521; i++) sum += b[i];
    b[522] = sum & 127;
    return dump;
}

static BOOL samePresetSound(NSData *first, NSData *second) {
    if (first.length != 524 || second.length != 524) return NO;
    const UInt8 *a = first.bytes, *b = second.bytes;
    // The Snow can rewrite patch-management flags and original bank/program in the edit buffer.
    return a[9] == b[9] && !memcmp(a + 13, b + 13, 252) && !memcmp(a + 266, b + 266, 256);
}

static NSData *matchingFrame(int bank, int program) {
    pthread_mutex_lock(&lock);
    NSData *found = nil;
    for (NSData *frame in frames) {
        NSDictionary *p = singlePreset(frame);
        if (p && [p[@"validated"] boolValue] && [p[@"bank"] intValue] == bank && [p[@"program"] intValue] == program) { found = frame; break; }
    }
    pthread_mutex_unlock(&lock);
    return found;
}

static NSString *parameterPrecondition(NSData *frame, const EditParameter *parameter, int expected, NSString *snapshot) {
    NSDictionary *decoded = frame ? singlePreset(frame) : nil;
    if (!decoded || ![decoded[@"validated"] boolValue]) return @"No valid current-buffer reply; edit refused";
    const UInt8 *b = frame.bytes;
    if (b[7] != 0 || !((b[8] <= 3) || b[8] == 64)) return @"Not a supported edit buffer; edit refused";
    if (!parameter || parameter->offset >= frame.length-1) return @"Unsupported parameter or preset format; edit refused";
    if (snapshot && ![packetDigest(frame) isEqualToString:snapshot]) return @"Sound changed since the last read; edit refused, read again";
    if (b[parameter->offset] != expected) return @"Parameter changed since the last read; edit refused, read again";
    BOOL enabled = parameter->guardAnd ? YES : NO;
    for (int i=0;i<parameter->guardCount;i++) {
        EditGuard guard = parameter->guards[i];
        if (guard.offset >= frame.length-1) return @"Condition data unavailable; edit refused";
        int value = b[guard.offset]; BOOL passed = NO;
        if (guard.kind==0) passed = value==guard.minimum;
        if (guard.kind==1) passed = value>=guard.minimum && value<=guard.maximum;
        if (guard.kind==2) passed = value<guard.minimum || value>guard.maximum;
        enabled = parameter->guardAnd ? enabled && passed : enabled || passed;
    }
    if (parameter->guardCount && parameter->guardInvert) enabled = !enabled;
    if (parameter->guardCount && !enabled) return @"Parameter is inactive or has another meaning in this mode; edit refused";
    return nil;
}
static NSString *cutoffPrecondition(NSData *frame, int expected) { return parameterPrecondition(frame,findParameter("Filter 1/Cutoff"),expected,nil); }

static void waitForPreset(int bank, int program) {
    NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 5;
    while (NSProcessInfo.processInfo.systemUptime < deadline) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
        if (matchingFrame(bank, program)) return;
    }
}

static BOOL integerArgument(const char *text, long *number) {
    char *end = NULL; *number = strtol(text, &end, 10);
    return *text && end && !*end;
}

typedef struct { char line[64]; unsigned used,total; int latest,finished,error; } LiveInput;
static void feedLiveInput(LiveInput *state, const char *bytes, size_t count, int minimum, int maximum) {
    for (size_t i=0;i<count && !state->finished && !state->error;i++) {
        if (++state->total > 65536) { state->error=1; break; }
        char byte=bytes[i];
        if (byte=='\n') {
            state->line[state->used]=0;
            if (!strcmp(state->line,"END")) state->finished=1;
            else if (state->used) {
                long value=0;
                if (!integerArgument(state->line,&value)) state->error=2;
                else if (value<minimum || value>maximum) state->error=3;
                else state->latest=(int)value;
            }
            state->used=0;
        } else if (state->used>=sizeof(state->line)-1 || byte<32 || byte>126) state->error=4;
        else state->line[state->used++]=byte;
    }
}

static OSStatus sendParameter(MIDIPortRef output, MIDIEndpointRef destination, const EditParameter *parameter, int target, int value) {
    if (!parameter || value<parameter->minimum || value>parameter->maximum) return -50;
    const UInt8 bytes[]={0xf0,0,0x20,0x33,1,0x10,(UInt8)parameter->page,(UInt8)target,(UInt8)parameter->controller,(UInt8)value,0xf7};
    MIDIPacketList list; MIDIPacket *packet=MIDIPacketListInit(&list);
    if (!MIDIPacketListAdd(&list,sizeof(list),packet,0,sizeof(bytes),bytes)) return -50;
    return MIDISend(output,destination,&list);
}

static void acceptBytes(const UInt8 *bytes, NSUInteger count) {
    for (NSUInteger i = 0; i < count; i++) {
        if (receivedBytes >= captureByteLimit) return;
        receivedBytes++;
        UInt8 b = bytes[i];
        byteHistogram[b]++;
        if (prefix.length < 128) [prefix appendBytes:&b length:1];
        if (b >= 0xf8) continue; // Real-time bytes can be interleaved with SysEx.
        if (b == 0xf0) { [partial setLength:0]; [partial appendBytes:&b length:1]; continue; }
        if (partial.length == 0) continue;
        if (b == 0xf7) {
            [partial appendBytes:&b length:1];
            if (frames.count < captureFrameLimit) [frames addObject:[partial copy]]; else discardedFrames++;
            [partial setLength:0];
        } else if (b & 0x80 || partial.length >= 4095) {
            discardedFrames++; [partial setLength:0];
        } else { [partial appendBytes:&b length:1]; }
    }
}

static void receive(const MIDIPacketList *list, void *context, void *sourceContext) {
    @autoreleasepool {
        pthread_mutex_lock(&lock);
        const MIDIPacket *packet = &list->packet[0];
        for (UInt32 i = 0; i < list->numPackets; i++) {
            packetCount++;
            smallestPacket = MIN(smallestPacket, packet->length);
            largestPacket = MAX(largestPacket, packet->length);
            acceptBytes(packet->data, packet->length);
            packet = MIDIPacketNext(packet);
        }
        pthread_mutex_unlock(&lock);
    }
}

static NSString *name(MIDIEndpointRef endpoint) {
    CFStringRef value = NULL;
    if (MIDIObjectGetStringProperty(endpoint, kMIDIPropertyDisplayName, &value) != noErr || !value) return @"";
    return CFBridgingRelease(value);
}

static NSString *hex(NSData *data) {
    NSMutableArray *parts = [NSMutableArray array]; const UInt8 *bytes = data.bytes;
    for (NSUInteger i = 0; i < data.length; i++) [parts addObject:[NSString stringWithFormat:@"%02X", bytes[i]]];
    return [parts componentsJoinedByString:@" "];
}

typedef struct USBReadCapture USBReadCapture;
typedef struct {
    USBReadCapture *capture;
    uint8_t events[64];
} USBReadSlot;

struct USBReadCapture {
    SnowUSB *usb;
    Boolean running;
    Boolean monitor;
    IOReturn status;
    USBReadSlot slots[2];
};

static void usbReadComplete(void *context, IOReturn status, void *byteCount);

static IOReturn queueUSBRead(USBReadSlot *slot) {
    SnowUSB *usb = slot->capture->usb;
    return (*usb->interface)->ReadPipeAsync(usb->interface, usb->inputPipe, slot->events,
                                            usb->inputSize, usbReadComplete, slot);
}

static void usbReadComplete(void *context, IOReturn status, void *byteCount) {
    USBReadSlot *slot = context;
    USBReadCapture *capture = slot->capture;
    if (!capture->running || capture->status) return;
    if (status) { capture->status = status; return; }
    size_t length = (uintptr_t)byteCount;
    if (length > capture->usb->inputSize) {
        capture->status = kIOReturnOverrun;
        return;
    }
    uint8_t midi[64];
    size_t midiCount = SnowUSBDecodePluginEvents(slot->events, length, midi);
    if (capture->monitor) {
        if (midiCount) {
            fwrite(midi, 1, midiCount, stdout);
            fflush(stdout);
        }
    } else {
        acceptBytes(midi, midiCount);
    }
    capture->status = queueUSBRead(slot);
}

static NSData *readUSBPreset(USBReadCapture *capture, UInt8 bank, UInt8 program, IOReturn *status, const char **stage) {
    UInt8 request[sizeof(presetRequestBytes)];
    memcpy(request, presetRequestBytes, sizeof(request));
    request[7] = bank; request[8] = program;
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        resetCapture();
        *stage = "Send Single edit-buffer read request";
        *status = SnowUSBWriteSysEx(capture->usb, request, sizeof(request));
        if (*status) return nil;

        *stage = "Read Single edit-buffer response";
        NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 2;
        while (!capture->status && NSProcessInfo.processInfo.systemUptime < deadline) {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.02, true);
            NSData *reply = matchingFrame(bank, program);
            if (reply.length == 524) return reply;
        }
        if (capture->status) { *status = capture->status; return nil; }
    }
    *status = kIOReturnTimeout;
    return nil;
}

static int streamParameter(const EditParameter *editParameter, int expected, NSMutableDictionary *result,
                           IOReturn (^send)(int)) {
    LiveInput input = {.latest = -1};
    int lastSent = expected;
    unsigned liveUpdates = 0;
    IOReturn status = 0;
    int flags=fcntl(STDIN_FILENO,F_GETFL);
    if (flags<0 || fcntl(STDIN_FILENO,F_SETFL,flags|O_NONBLOCK)<0) { result[@"liveInputError"] = @5; return expected; }
    NSTimeInterval deadline=NSProcessInfo.processInfo.systemUptime+30, lastTime=0;
    while (!input.finished && !input.error && NSProcessInfo.processInfo.systemUptime<deadline) {
        char bytes[256]; ssize_t count;
        while ((count=read(STDIN_FILENO,bytes,sizeof(bytes)))>0) {
            feedLiveInput(&input,bytes,(size_t)count,editParameter->minimum,editParameter->maximum);
            if (input.finished || input.error) break;
        }
        if (count==0) {
            if (input.used) feedLiveInput(&input,"\n",1,editParameter->minimum,editParameter->maximum);
            input.finished=1;
        } else if (count<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) input.error=5;
        NSTimeInterval now=NSProcessInfo.processInfo.systemUptime;
        if (!input.error && input.latest>=0 && input.latest!=lastSent && now-lastTime>=1.0/30) {
            status=send(input.latest);
            if (status) { input.error=6; result[@"OSStatus"]=@(status); break; }
            lastSent=input.latest; liveUpdates++; lastTime=now;
        }
        if (!input.finished && !input.error) CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.01,false);
    }
    if (!input.error && input.latest>=0 && input.latest!=lastSent) {
        status=send(input.latest);
        if (!status) { lastSent=input.latest; liveUpdates++; } else { input.error=6; result[@"OSStatus"]=@(status); }
    }
    fcntl(STDIN_FILENO,F_SETFL,flags);
    result[@"liveUpdatesSent"]=@(liveUpdates); result[@"lastLiveValue"]=@(lastSent);
    if (input.error) result[@"liveInputError"]=@(input.error);
    if (!input.finished && !input.error) result[@"liveTimedOut"]=@YES;
    return lastSent;
}

static IOReturn writeUSBParameter(SnowUSB *usb, const EditParameter *parameter, int value) {
    const UInt8 command[] = {0xf0,0,0x20,0x33,1,0x10,parameter->page,64,
                             parameter->controller,(UInt8)value,0xf7};
    return SnowUSBWriteSysEx(usb, command, sizeof(command));
}

static NSData *readUSBRAM(USBReadCapture *capture, unsigned bankCount, IOReturn *status) {
    NSMutableData *library = [NSMutableData dataWithCapacity:bankCount * 128 * 524];
    captureByteLimit = 256 * 1024;
    captureFrameLimit = 256;
    for (unsigned bank = 1; bank <= bankCount; bank++) {
        NSData *programs[128] = {nil};
        unsigned count = 0;
        // The Snow paces bank dumps more slowly than individually requested programs over USB.
        for (unsigned i = 0; i < 128; i++) {
            const char *stage = NULL;
            programs[i] = readUSBPreset(capture, (UInt8)bank, (UInt8)i, status, &stage);
            if (!programs[i]) {
                if (*status != kIOReturnTimeout || capture->status) return nil;
                break;
            }
            count++;
            fprintf(stderr, "RAM progress %u\n", (bank - 1) * 128 + count);
        }
        if (count < 128) {
            resetCapture();
            const UInt8 request[] = {0xf0,0,0x20,0x33,1,0x10,0x32,(UInt8)bank,0xf7};
            *status = SnowUSBWriteSysEx(capture->usb, request, sizeof(request));
            if (*status) return nil;
            NSUInteger inspected = 0;
            NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 5;
            while (!capture->status && count < 128 && NSProcessInfo.processInfo.systemUptime < deadline) {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, false);
                while (inspected < frames.count) {
                    NSData *frame = frames[inspected++];
                    const UInt8 *bytes = frame.bytes;
                    if (frame.length != 524 || bytes[7] != bank || bytes[8] >= 128 ||
                        ![singlePreset(frame)[@"validated"] boolValue]) continue;
                    deadline = NSProcessInfo.processInfo.systemUptime + 3;
                    if (programs[bytes[8]]) continue;
                    programs[bytes[8]] = frame;
                    count++;
                    fprintf(stderr, "RAM progress %u\n", (bank - 1) * 128 + count);
                }
            }
            if (capture->status) {
                *status = capture->status;
                return nil;
            }
        }
        // Recover missing slots with individual read requests after the bank stream falls silent.
        for (unsigned i = 0; i < 128; i++) {
            if (!programs[i]) {
                const char *stage = NULL;
                programs[i] = readUSBPreset(capture, (UInt8)bank, (UInt8)i, status, &stage);
                if (!programs[i]) return nil;
                count++;
                fprintf(stderr, "RAM progress %u\n", (bank - 1) * 128 + count);
            }
            [library appendData:programs[i]];
        }
    }
    return library;
}

static int directUSBProbe(BOOL readCurrent, BOOL jsonOutput, const EditParameter *parameter,
                          int desired, int expected, NSString *digest, BOOL live, NSData *factoryDump, BOOL monitor, unsigned ramBanks) {
    NSMutableDictionary *details = [NSMutableDictionary dictionary];
    NSString *editResult = nil;
    BOOL verified = NO;
    SnowUSB usb;
    const char *stage = NULL;
    IOReturn status = SnowUSBOpen(&usb, &stage);
    NSData *reply = nil;
    NSData *ramLibrary = nil;
    USBReadCapture capture = { .usb = &usb, .running = true, .monitor = monitor };
    CFRunLoopSourceRef source = NULL;
    if (!status && readCurrent) {
        resetCapture();
        stage = "Queue USB MIDI input";
        status = (*usb.interface)->CreateInterfaceAsyncEventSource(usb.interface, &source);
        if (!status) {
            CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
            // Keep a read queued while its peer completes so Active Sensing traffic cannot crowd out the dump.
            for (unsigned i=0; i<2 && !status; i++) {
                capture.slots[i].capture = &capture;
                status = queueUSBRead(&capture.slots[i]);
            }
        }
        if (!status) {
            stage = "Initialize USB MIDI interface";
            status = SnowUSBStart(&usb);
        }
        if (!status && monitor) {
            stage = "Monitor Single-mode USB MIDI";
            int flags = fcntl(STDIN_FILENO, F_GETFL);
            if (flags < 0 || fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) < 0) {
                status = kIOReturnError;
            } else {
                while (!capture.status) {
                    char unused;
                    ssize_t count = read(STDIN_FILENO, &unused, 1);
                    if (count == 0) break;
                    if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                        status = kIOReturnError;
                        break;
                    }
                    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, false);
                }
                if (capture.status) status = capture.status;
            }
        } else if (!status && ramBanks) {
            stage = "Read custom RAM banks";
            ramLibrary = readUSBRAM(&capture, ramBanks, &status);
        } else if (!status) {
            reply = readUSBPreset(&capture, 0, 64, &status, &stage);
        }
        if (reply && parameter) {
            editResult = parameterPrecondition(reply, parameter, expected, digest);
            if (!editResult) {
                stage = "Send Single edit-buffer parameter change";
                if (live) {
                    SnowUSB *transport = &usb;
                    desired = streamParameter(parameter, expected, details, ^IOReturn(int value) {
                        return writeUSBParameter(transport, parameter, value);
                    });
                } else {
                    status = writeUSBParameter(&usb, parameter, desired);
                }
                reply = status ? nil : readUSBPreset(&capture, 0, 64, &status, &stage);
                if (reply) {
                    verified = ((const UInt8 *)reply.bytes)[parameter->offset] == desired;
                    editResult = verified ? @"Parameter verified by direct USB readback"
                                          : @"Parameter sent, but direct USB readback differs";
                }
            }
        }
        if (reply && factoryDump) {
            if (![packetDigest(reply) isEqualToString:digest]) {
                editResult = @"Sound changed since the last read; load refused, read again";
            } else {
                stage = "Send factory sound to Single edit buffer";
                status = SnowUSBWriteSysEx(&usb, factoryDump.bytes, factoryDump.length);
                if (!status) CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.2, false);
                reply = status ? nil : readUSBPreset(&capture, 0, 64, &status, &stage);
                verified = samePresetSound(factoryDump, reply);
                editResult = verified ? @"Factory sound loaded and verified over direct USB"
                                      : @"Factory sound load could not be verified";
            }
        }
    }
    capture.running = false;
    if (source) {
        (*usb.interface)->AbortPipe(usb.interface, usb.inputPipe);
        CFRunLoopRemoveSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
        CFRelease(source);
    }
    if (ramLibrary) {
        fwrite(ramLibrary.bytes, 1, ramLibrary.length, stdout);
    } else if (jsonOutput && reply) {
        NSMutableDictionary *report = details;
        report[@"receivedSysExHex"] = @[hex(reply)];
        if (parameter) {
            report[@"parameterWriteVerified"] = @(verified);
            report[@"status"] = editResult;
        }
        if (factoryDump) {
            report[@"factoryLoadVerified"] = @(verified);
            report[@"status"] = editResult;
        }
        NSData *json = [NSJSONSerialization dataWithJSONObject:report options:0 error:NULL];
        if (json) fwrite(json.bytes, 1, json.length, stdout);
        else status = kIOReturnError;
    } else if (!status && !monitor) {
        printf("Snow USB interface 3 opened. Packet sizes: IN %u, OUT %u.\n", usb.inputSize, usb.outputSize);
        if (reply) printf("%s\n", singlePreset(reply).description.UTF8String);
        else puts("No bytes sent.");
    } else if (status) {
        fprintf(stderr, "%s failed (0x%08x).\n", stage, (unsigned)status);
    }
    SnowUSBClose(&usb);
    return status || ((parameter || factoryDump) && !verified) ? 1 : 0;
}

static int selfTest(void) {
    const uint8_t request[] = {0xf0,0,0x20,0x33,1,0x10,0x30,0,0x40,0xf7};
    const uint8_t expectedEvents[] = {0x14,0xf0,0,0x20,0x14,0x33,1,0x10,0x14,0x30,0,0x40,0x15,0xf7,0,0};
    uint8_t usbEvents[704] = {0}, usbDecoded[528];
    size_t encoded = SnowUSBEncodeSysEx(request, sizeof(request), usbEvents, sizeof(usbEvents));
    NSCAssert(encoded == sizeof(expectedEvents) && !memcmp(usbEvents, expectedEvents, encoded), @"USB-MIDI Plugin I/O framing");
    const uint8_t mixedEvents[] = {0,0,0,0,0x04,0xf0,1,2,0x17,3,4,0xf7};
    NSCAssert(SnowUSBDecodePluginEvents(mixedEvents, sizeof(mixedEvents), usbDecoded) == 3
              && usbDecoded[0] == 3 && usbDecoded[2] == 0xf7, @"USB MIDI input filters padding and External I/O");
    resetCapture();
    const UInt8 reply[] = {0xf0,0x7e,0x01,0x06,0x02,0x00,0x20,0x33,0x01,0x00,0x02,0x00,0x05,0x01,0x07,0x00,0xf7};
    acceptBytes(reply, 7);
    const UInt8 realtime = 0xf8; acceptBytes(&realtime, 1);
    acceptBytes(reply+7, sizeof(reply)-7);
    NSCAssert(frames.count == 1, @"fragment/realtime reassembly");
    NSDictionary *decoded = identity(frames[0]);
    NSCAssert(decoded && [decoded[@"family"] intValue] == 1 && [decoded[@"member"] intValue] == 2, @"extended identity");
    NSCAssert(identity([NSData dataWithBytes:requestBytes length:sizeof(requestBytes)]) == nil, @"request echo is not reply");
    const UInt8 oneByteManufacturer[] = {0xf0,0x7e,0,6,2,0x41,1,0,2,0,1,2,3,4,0xf7};
    NSCAssert(identity([NSData dataWithBytes:oneByteManufacturer length:sizeof(oneByteManufacturer)]) != nil, @"short manufacturer");
    resetCapture(); const UInt8 broken[] = {0xf0,1,0x90,0,0xf7}; acceptBytes(broken,sizeof(broken));
    NSCAssert(frames.count == 0 && discardedFrames == 1, @"invalid status abort");
    resetCapture(); UInt8 garbage[70000]; memset(garbage, 0x01, sizeof(garbage)); acceptBytes(garbage,sizeof(garbage));
    NSCAssert(receivedBytes == 65536, @"input cap");
    NSMutableData *single = [NSMutableData dataWithLength:524]; UInt8 *b = single.mutableBytes;
    memcpy(b, "\xf0\x00\x20\x33\x01", 5); b[5]=0x10; b[6]=0x10; b[7]=1; b[8]=0;
    memcpy(b+249, "Test Patch", 10); b[523]=0xf7;
    unsigned sum=0; for (NSUInteger i=5;i<=264;i++) sum+=b[i]; b[265]=sum & 127;
    sum=0; for (NSUInteger i=5;i<=521;i++) sum+=b[i]; b[522]=sum & 127;
    NSCAssert([singlePreset(single)[@"validated"] boolValue], @"TI dual checksums");
    encoded = SnowUSBEncodeSysEx(b, single.length, usbEvents, sizeof(usbEvents));
    NSCAssert(encoded == 700 && SnowUSBDecodePluginEvents(usbEvents, encoded, usbDecoded) == single.length
              && !memcmp(b, usbDecoded, single.length), @"524-byte dump round-trips through USB event framing");
    NSData *audition = factorySingleDump(single);
    NSDictionary *decodedAudition = singlePreset(audition);
    NSCAssert([decodedAudition[@"validated"] boolValue] && [decodedAudition[@"bank"] intValue] == 0
              && [decodedAudition[@"program"] intValue] == 64 && samePresetSound(single, audition),
              @"Factory load is a checksum-valid Single edit-buffer dump with unchanged sound bytes");
    b[30] ^= 1;
    NSCAssert(factorySingleDump(single) == nil && !samePresetSound(single, audition), @"Corrupt source rejected");
    NSCAssert(![singlePreset(single)[@"validated"] boolValue], @"preset corruption detection");
    // Exercise write preconditions without creating MIDI clients or sending messages.
    b[30] ^= 1; b[7] = 0; b[8] = 64; b[49] = 40; b[176] = 0;
    sum=0; for (NSUInteger i=5;i<=264;i++) sum+=b[i]; b[265]=sum & 127;
    sum=0; for (NSUInteger i=5;i<=521;i++) sum+=b[i]; b[522]=sum & 127;
    NSCAssert(cutoffPrecondition(single,40) == nil, @"valid live-buffer preflight");
    NSCAssert(cutoffPrecondition(single,41) != nil, @"changed cutoff refuses write");
    b[176]=1;
    sum=0; for (NSUInteger i=5;i<=264;i++) sum+=b[i]; b[265]=sum & 127;
    sum=0; for (NSUInteger i=5;i<=521;i++) sum+=b[i]; b[522]=sum & 127;
    NSCAssert(cutoffPrecondition(single,40) != nil, @"vocoder refuses cutoff alias write");
    NSCAssert(editParameterCount == GENERATED_EDIT_PARAMETER_COUNT, @"generated allowlist count");
    for (unsigned i=0;i<editParameterCount;i++) {
        const EditParameter *p = &editParameters[i];
        NSCAssert(p->offset>=9 && p->offset<=521 && p->offset!=265, @"single-dump byte mapping");
        NSCAssert(p->minimum>=0 && p->maximum<=127 && p->controller>=0 && p->controller<=127, @"bounded edit mapping");
    }
    NSCAssert(findParameter("Global Master/Mode")==NULL, @"global settings excluded");
    NSCAssert(parameterPrecondition(single,findParameter("Filter 1/Cutoff"),40,@"stale") != nil, @"stale snapshot refused");
    b[176]=0;
    sum=0; for (NSUInteger i=5;i<=264;i++) sum+=b[i]; b[265]=sum & 127;
    sum=0; for (NSUInteger i=5;i<=521;i++) sum+=b[i]; b[522]=sum & 127;
    NSCAssert(parameterPrecondition(single,findParameter("Filter 1/Cutoff"),40,packetDigest(single)) == nil, @"matching snapshot accepted");
    NSCAssert(parameterPrecondition(single,findParameter("Filter 1/Cutoff"),41,packetDigest(single)) != nil, @"changed parameter refused");
    LiveInput input={.latest=-1}; feedLiveInput(&input,"63\n6",4,0,127); feedLiveInput(&input,"4\n65\nEND\n",9,0,127);
    NSCAssert(input.latest==65 && input.finished && !input.error,@"fragmented live input coalesces to final value");
    LiveInput bad={.latest=-1}; feedLiveInput(&bad,"128\n",4,0,127);
    NSCAssert(bad.error && bad.latest==-1,@"out-of-range live input refused");
    LiveInput malformed={.latest=-1}; feedLiveInput(&malformed,"F0 70\n",6,0,127);
    NSCAssert(malformed.error,@"arbitrary live bytes refused");
    puts("PASS: fragmented SysEx, interleaved realtime, identity validation, echo rejection, malformed input, input cap");
    return 0;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return selfTest();
        if (argc == 2 && strcmp(argv[1], "--usb-read-ram") == 0)
            return directUSBProbe(YES, NO, NULL, 0, 0, nil, NO, nil, NO, 4);
        if (argc == 2 && strcmp(argv[1], "--usb-monitor") == 0)
            return directUSBProbe(YES, NO, NULL, 0, 0, nil, NO, nil, YES, 0);
        if (argc == 2 && strcmp(argv[1], "--usb-status") == 0) return directUSBProbe(NO, NO, NULL, 0, 0, nil, NO, nil, NO, 0);
        if (argc == 2 && strcmp(argv[1], "--usb-read-current") == 0) return directUSBProbe(YES, NO, NULL, 0, 0, nil, NO, nil, NO, 0);
        if (argc == 3 && strcmp(argv[1], "--usb-read-current") == 0 && strcmp(argv[2], "--json") == 0) return directUSBProbe(YES, YES, NULL, 0, 0, nil, NO, nil, NO, 0);
        if (argc == 3 && strcmp(argv[1], "--decode-preset") == 0) {
            NSData *data = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[2]]];
            NSDictionary *decoded = data ? singlePreset(data) : nil;
            if (!decoded) { fprintf(stderr,"Not a supported single preset dump\n"); return 1; }
            NSData *json = [NSJSONSerialization dataWithJSONObject:decoded options:NSJSONWritingPrettyPrinted error:nil];
            fwrite(json.bytes,1,json.length,stdout); puts("");
            return [decoded[@"validated"] boolValue] ? 0 : 1;
        }
        BOOL passive = argc == 2 && strcmp(argv[1], "--listen-only") == 0;
        BOOL presetRequest = argc == 2 && strcmp(argv[1], "--request-preset") == 0;
        BOOL selectedPreset = argc == 4 && strcmp(argv[1], "--read-preset") == 0;
        BOOL currentRead = argc == 3 && strcmp(argv[1], "--read-current") == 0;
        BOOL usbFactoryLoad = argc == 4 && strcmp(argv[1], "--usb-load-factory-single") == 0;
        BOOL factoryLoad = usbFactoryLoad || (argc == 4 && strcmp(argv[1], "--load-factory-single") == 0);
        NSData *factoryDump = factoryLoad ? factorySingleDump([[NSData alloc]
            initWithBase64EncodedString:[NSString stringWithUTF8String:argv[2]] options:0]) : nil;
        if (factoryLoad && !factoryDump) {
            fprintf(stderr,"Invalid factory preset dump; nothing sent\n"); return 2;
        }
        BOOL usbWrite = argc == 7 && strcmp(argv[1], "--usb-set-parameter") == 0;
        BOOL genericWrite = usbWrite || (argc == 7 && strcmp(argv[1], "--set-parameter") == 0);
        BOOL usbLive = argc == 6 && strcmp(argv[1], "--usb-live-edit") == 0;
        BOOL liveWrite = usbLive || (argc == 6 && strcmp(argv[1], "--live-edit") == 0);
        BOOL cutoffWrite = genericWrite || liveWrite || (argc == 5 && strcmp(argv[1], "--set-cutoff") == 0);
        const EditParameter *editParameter = (genericWrite || liveWrite) ? findParameter(argv[3]) : findParameter("Filter 1/Cutoff");
        NSString *expectedSnapshot = factoryLoad ? [NSString stringWithUTF8String:argv[3]] : (genericWrite || liveWrite) ? [NSString stringWithUTF8String:argv[liveWrite?5:6]] : nil;
        if ((genericWrite || liveWrite || factoryLoad) && ((!factoryLoad && !editParameter) || expectedSnapshot.length != 64 || [expectedSnapshot rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location != NSNotFound)) {
            fprintf(stderr,"Unknown parameter or invalid snapshot digest; nothing sent\n"); return 2;
        }
        long editTarget = -1, cutoffValue = -1, expectedCutoff = -1;
        if (currentRead || cutoffWrite) {
            if (!integerArgument(argv[2], &editTarget) || !((editTarget >= 0 && editTarget <= 3) || editTarget == 64)) {
                fprintf(stderr,"Edit-buffer target must be 0..3 or 64; nothing sent\n"); return 2;
            }
            if (cutoffWrite && (!integerArgument(argv[liveWrite?4:genericWrite?4:3], &cutoffValue) || !integerArgument(argv[liveWrite?4:genericWrite?5:4], &expectedCutoff) || (!liveWrite && (cutoffValue < editParameter->minimum || cutoffValue > editParameter->maximum)) || expectedCutoff < 0 || expectedCutoff > 127)) {
                fprintf(stderr,"Parameter value outside its allowed range; nothing sent\n"); return 2;
            }
        }
        if (usbFactoryLoad) return directUSBProbe(YES, YES, NULL, 0, 0, expectedSnapshot, NO, factoryDump, NO, 0);
        if (usbWrite || usbLive) {
            if (editTarget != 64) { fprintf(stderr,"Direct USB editing requires Single mode\n"); return 2; }
            return directUSBProbe(YES, YES, editParameter, (int)cutoffValue, (int)expectedCutoff, expectedSnapshot, usbLive, nil, NO, 0);
        }
        UInt8 selectedBytes[sizeof(presetRequestBytes)]; memcpy(selectedBytes,presetRequestBytes,sizeof(selectedBytes));
        int requestedBank = 1, requestedProgram = 0;
        if (currentRead || cutoffWrite) {
            requestedBank = 0; requestedProgram = (int)editTarget;
            selectedBytes[7] = 0; selectedBytes[8] = (UInt8)editTarget; presetRequest = YES;
        }
        if (factoryLoad) {
            requestedBank = 0; requestedProgram = 64;
            selectedBytes[7] = 0; selectedBytes[8] = 64; presetRequest = YES;
        }
        if (selectedPreset) {
            char *bankEnd = NULL, *programEnd = NULL;
            long bank = strtol(argv[2], &bankEnd, 10), program = strtol(argv[3], &programEnd, 10);
            if (!*argv[2] || !*argv[3] || *bankEnd || *programEnd || bank < 1 || bank > 127 || program < 0 || program > 127) {
                fprintf(stderr,"Read requires bank 1..127 and program 0..127; nothing sent\n"); return 2;
            }
            requestedBank = (int)bank; requestedProgram = (int)program;
            selectedBytes[7] = (UInt8)bank; selectedBytes[8] = (UInt8)program; presetRequest = YES;
        }
        if (argc != 1 && !passive && !presetRequest) { fprintf(stderr,"Usage: virus-identity-probe [--self-test | --listen-only | --request-preset | --read-preset BANK PROGRAM | --decode-preset FILE]\n"); return 2; }
        const UInt8 *outbound = presetRequest ? selectedBytes : requestBytes;
        NSUInteger outboundLength = presetRequest ? sizeof(presetRequestBytes) : sizeof(requestBytes);
        resetCapture();
        NSMutableDictionary *result = [@{ @"test": @"Universal MIDI identity request", @"endpoint": @"Virus TI USB Plugin I/O",
            @"outboundHex": @"F0 7E 7F 06 01 F7", @"listenSeconds": @5,
            @"status": @"not started", @"messagesSent": @0 } mutableCopy];
        if (passive) { result[@"test"] = @"Passive Plugin I/O stream capture"; result[@"outboundHex"] = @""; }
        if (presetRequest) {
            result[@"test"] = (currentRead || cutoffWrite || factoryLoad) ? @"Current edit-buffer access" : @"Read stored preset; no program change or write";
            result[@"requestedBank"] = @(requestedBank); result[@"requestedProgram"] = @(requestedProgram);
            result[@"outboundHex"] = hex([NSData dataWithBytes:outbound length:outboundLength]);
        }
        if (cutoffWrite) result[@"maximumListenSeconds"] = liveWrite ? @40 : @10;
        if (cutoffWrite) result[@"parameterID"] = [NSString stringWithUTF8String:editParameter->key];
        MIDIClientRef client = 0; MIDIPortRef input = 0, output = 0;
        MIDIEndpointRef source = 0, destination = 0;
        OSStatus status = MIDIClientCreate(CFSTR("Virus Identity Probe"), NULL, NULL, &client);
        if (status) { result[@"status"] = @"CoreMIDI initialization failed"; result[@"OSStatus"] = @(status); goto finish; }
        unsigned sourceCount = 0, destinationCount = 0;
        for (ItemCount i = 0; i < MIDIGetNumberOfSources(); i++) {
            MIDIEndpointRef e = MIDIGetSource(i);
            if ([name(e) isEqualToString:result[@"endpoint"]]) { source = e; sourceCount++; }
        }
        for (ItemCount i = 0; i < MIDIGetNumberOfDestinations(); i++) {
            MIDIEndpointRef e = MIDIGetDestination(i);
            if ([name(e) isEqualToString:result[@"endpoint"]]) { destination = e; destinationCount++; }
        }
        if (sourceCount != 1 || destinationCount != 1) {
            result[@"status"] = @"Missing or ambiguous Plugin I/O endpoint; nothing sent";
            result[@"sourceMatches"] = @(sourceCount); result[@"destinationMatches"] = @(destinationCount); goto finish;
        }
        status = MIDIInputPortCreate(client, CFSTR("Identity Reply"), receive, NULL, &input);
        if (!status) status = MIDIPortConnectSource(input, source, NULL);
        if (!status) status = MIDIOutputPortCreate(client, CFSTR("Identity Request"), &output);
        if (status) { result[@"status"] = @"MIDI port setup failed; nothing sent"; result[@"OSStatus"] = @(status); goto finish; }
        {
            MIDIPacketList list; MIDIPacket *packet = MIDIPacketListInit(&list);
            if (!MIDIPacketListAdd(&list, sizeof(list), packet, 0, outboundLength, outbound)) {
                result[@"status"] = @"Packet construction failed; nothing sent"; goto finish;
            }
            status = passive ? noErr : MIDISend(output, destination, &list);
            if (status) { result[@"status"] = @"MIDI send failed"; result[@"OSStatus"] = @(status); goto finish; }
            result[@"messagesSent"] = passive ? @0 : @1;
            if (presetRequest) waitForPreset(requestedBank, requestedProgram);
            else {
                NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 5;
                while (NSProcessInfo.processInfo.systemUptime < deadline) CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
            }
            result[@"status"] = passive ? @"Passive capture complete; no request sent" : @"No identity reply observed; support and communication remain unconfirmed";
            if (presetRequest) result[@"status"] = @"No validated matching preset reply observed; support and routing remain unconfirmed";
            if (factoryLoad) {
                NSData *preflight = matchingFrame(0, 64);
                if (preflight.length != 524 || ![packetDigest(preflight) isEqualToString:expectedSnapshot]) {
                    result[@"status"] = @"Current sound could not be confirmed or changed since the last read. Read it again before loading.";
                    goto finish;
                }
                // Give CoreMIDI room for the entire SysEx, beyond MIDIPacket's inline data.
                union { MIDIPacketList list; UInt8 storage[1024]; } dumpList;
                MIDIPacket *dumpPacket = MIDIPacketListInit(&dumpList.list);
                if (!MIDIPacketListAdd(&dumpList.list, sizeof(dumpList), dumpPacket, 0, factoryDump.length, factoryDump.bytes)) {
                    result[@"status"] = @"Factory dump packet construction failed"; goto finish;
                }
                status = MIDISend(output, destination, &dumpList.list);
                if (status) { result[@"status"] = @"Factory dump send failed"; result[@"OSStatus"] = @(status); goto finish; }
                result[@"messagesSent"] = @2;
                // Allow the synth to process the dump and discard any immediate MIDI echo.
                usleep(200000);
                pthread_mutex_lock(&lock); resetCapture(); pthread_mutex_unlock(&lock);
                status = MIDISend(output, destination, &list);
                if (status) { result[@"status"] = @"Factory dump sent; readback request failed"; result[@"OSStatus"] = @(status); goto finish; }
                result[@"messagesSent"] = @3;
                waitForPreset(0, 64);
                NSData *readback = matchingFrame(0, 64);
                BOOL verified = samePresetSound(factoryDump, readback);
                result[@"factoryLoadVerified"] = @(verified);
                result[@"status"] = verified ? @"Factory sound loaded and verified by checksum-valid readback"
                    : readback ? @"Factory dump sent; the returned sound bytes differ" : @"Factory dump sent; no validated readback received";
            }
            if (cutoffWrite) {
                NSData *preflight = matchingFrame(0, (int)editTarget);
                result[@"cutoffWriteAccepted"] = @NO; result[@"desiredCutoff"] = @(cutoffValue);
                if (!preflight) { result[@"status"] = @"No current-buffer reply; edit refused"; goto finish; }
                const UInt8 *b = preflight.bytes;
                NSString *refusal = parameterPrecondition(preflight,editParameter,(int)expectedCutoff,expectedSnapshot);
                if (refusal) { result[@"status"] = refusal; goto finish; }
                result[@"preflightValue"] = @(b[editParameter->offset]);
                unsigned liveUpdates=0;
                if (liveWrite) {
                    cutoffValue = streamParameter(editParameter, (int)expectedCutoff, result, ^IOReturn(int value) {
                        return sendParameter(output, destination, editParameter, (int)editTarget, value);
                    });
                    liveUpdates = [result[@"liveUpdatesSent"] unsignedIntValue];
                    result[@"messagesSent"]=@(liveUpdates+1);
                } else {
                    status=sendParameter(output,destination,editParameter,(int)editTarget,(int)cutoffValue);
                    if (status) { result[@"status"]=@"Parameter send failed"; result[@"OSStatus"]=@(status); goto finish; }
                    result[@"messagesSent"]=@2;
                }
                result[@"cutoffWriteAccepted"] = @YES;
                // Read back in port order; retain only the readback capture from this point.
                pthread_mutex_lock(&lock); resetCapture(); pthread_mutex_unlock(&lock);
                status = MIDISend(output,destination,&list);
                if (status) { result[@"status"] = @"Parameter sent; readback request failed"; result[@"OSStatus"] = @(status); goto finish; }
                result[@"messagesSent"] = liveWrite ? @(liveUpdates+2) : @3; result[@"capturePhase"] = @"readback";
                waitForPreset(0,(int)editTarget);
                result[@"status"] = @"Parameter sent; no verified readback observed";
            }
        }
    finish:
        if (input && source) MIDIPortDisconnectSource(input, source);
        if (input) MIDIPortDispose(input);
        if (output) MIDIPortDispose(output);
        if (client) MIDIClientDispose(client);
        pthread_mutex_lock(&lock);
        NSMutableArray *messages = [NSMutableArray array];
        NSMutableArray *presets = [NSMutableArray array];
        for (NSData *frame in frames) {
            [messages addObject:hex(frame)];
            NSDictionary *decoded = identity(frame);
            if (decoded && !factoryLoad) { result[@"identity"] = decoded; result[@"status"] = @"Identity reply observed on Plugin I/O"; }
            NSDictionary *preset = singlePreset(frame);
            if (preset) {
                [presets addObject:preset];
                if (presetRequest && [preset[@"validated"] boolValue] && [preset[@"bank"] intValue] == requestedBank && [preset[@"program"] intValue] == requestedProgram) {
                    if (!cutoffWrite && !factoryLoad) result[@"status"] = @"Validated matching preset reply observed on Plugin I/O";
                    else if ([result[@"cutoffWriteAccepted"] boolValue]) {
                        const UInt8 *b = frame.bytes;
                        BOOL verified = b[editParameter->offset] == cutoffValue;
                        result[@"cutoffWriteVerified"] = @(verified);
                        result[@"parameterWriteVerified"] = @(verified);
                        result[@"status"] = verified ? @"Parameter edit verified by checksum-valid readback" : @"Parameter sent; readback value differs";
                    }
                }
            }
        }
        result[@"receivedSysExHex"] = messages; result[@"receivedBytes"] = @(receivedBytes);
        result[@"presetReplies"] = presets;
        result[@"discardedFrames"] = @(discardedFrames); result[@"incompleteFrameBytes"] = @(partial.length);
        NSMutableDictionary *histogram = [NSMutableDictionary dictionary];
        for (NSUInteger i = 0; i < 256; i++) if (byteHistogram[i]) histogram[[NSString stringWithFormat:@"%02lX", (unsigned long)i]] = @(byteHistogram[i]);
        result[@"byteHistogram"] = histogram; result[@"first128BytesHex"] = hex(prefix);
        result[@"packetCount"] = @(packetCount); result[@"smallestPacket"] = @(packetCount ? smallestPacket : 0); result[@"largestPacket"] = @(largestPacket);
        pthread_mutex_unlock(&lock);
        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted|NSJSONWritingSortedKeys error:&error];
        if (!json) { fprintf(stderr,"Cannot encode result\n"); return 1; }
        fwrite(json.bytes,1,json.length,stdout); puts("");
        // App integration consumes stdout; do not write into the app bundle.
        if (selectedPreset || currentRead || cutoffWrite) return ([result[@"status"] isEqualToString:@"Validated matching preset reply observed on Plugin I/O"] || [result[@"cutoffWriteVerified"] boolValue]) ? 0 : 1;
        return ([result[@"status"] isEqualToString:@"Identity reply observed on Plugin I/O"] || [result[@"status"] isEqualToString:@"Passive capture complete; no request sent"] || [result[@"status"] isEqualToString:@"Validated matching preset reply observed on Plugin I/O"]) ? 0 : 1;
    }
}
