"""Read-only Virus preset/parameter extraction from the user's installer.

No MIDI sending. No third-party Python dependencies. Python 3.9+.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET


def vlq(data, offset):
    value = 0
    for _ in range(4):
        if offset >= len(data):
            raise ValueError('Truncated MIDI variable-length quantity')
        byte = data[offset]
        offset += 1
        value = (value << 7) | (byte & 127)
        if byte < 128:
            return value, offset
    raise ValueError('Oversized MIDI variable-length quantity')


def smf_sysex(data):
    if data[:4] != b'MThd' or len(data) < 14:
        raise ValueError('Not a Standard MIDI File')
    header_size = int.from_bytes(data[4:8], 'big')
    if header_size < 6 or header_size + 8 > len(data):
        raise ValueError('Invalid MIDI header')
    offset = 8 + header_size
    while offset < len(data):
        if offset + 8 > len(data):
            raise ValueError('Truncated MIDI chunk')
        tag, size = data[offset:offset+4], int.from_bytes(data[offset+4:offset+8], 'big')
        offset += 8
        end = offset + size
        if end > len(data):
            raise ValueError('Truncated MIDI track')
        track = data[offset:end]
        offset = end
        if tag != b'MTrk':
            continue
        index, running, pending = 0, None, bytearray()
        while index < len(track):
            _, index = vlq(track, index)
            if index >= len(track):
                raise ValueError('Missing MIDI event')
            status = track[index]
            if status >= 128:
                index += 1
                running = status if status < 0xf0 else None
            elif running is None:
                raise ValueError('Missing MIDI running status')
            else:
                status = running
            if status in (0xf0, 0xf7, 0xff):
                if status == 0xff:
                    index += 1  # Meta event type
                length, index = vlq(track, index)
                if index + length > len(track):
                    raise ValueError('Truncated MIDI payload')
                payload = track[index:index+length]
                index += length
                if status == 0xff:
                    continue
                if status == 0xf0:
                    if pending:
                        raise ValueError('Unterminated MIDI SysEx')
                    pending = bytearray(b'\xf0')
                elif not pending:
                    continue  # An SMF escape event, not a continued SysEx.
                pending.extend(payload)
                if pending and pending[-1] == 0xf7:
                    yield bytes(pending)
                    pending.clear()
            elif status < 0xf0:
                length = 1 if status >> 4 in (0xc, 0xd) else 2
                if index + length > len(track) or any(b >= 128 for b in track[index:index+length]):
                    raise ValueError('Invalid MIDI channel event')
                index += length
            else:
                raise ValueError('Unsupported MIDI system event in SMF')
        if pending:
            raise ValueError('Unterminated SysEx at track end')


def decode_single(frame):
    if len(frame) not in (267, 524) or frame[:5] != bytes.fromhex('f0 00 20 33 01') or frame[6] != 0x10 or frame[-1] != 0xf7:
        return None
    if any(byte >= 128 for byte in frame[1:-1]):
        raise ValueError('Non-7-bit preset payload')
    checks = [(265, 5, 264)]
    if len(frame) == 524:
        checks.append((522, 5, 521))
    for at, first, last in checks:
        if sum(frame[first:last+1]) & 127 != frame[at]:
            raise ValueError('Preset checksum mismatch at %d' % at)
    return {'format': 'VirusTI_Singledump' if len(frame) == 524 else 'VirusC_Singledump',
            'deviceID': frame[5], 'bank': frame[7], 'program': frame[8],
            'name': frame[249:259].decode('ascii').rstrip(),
            'bytes': len(frame), 'sha256': hashlib.sha256(frame).hexdigest(),
            'checksumCount': len(checks)}


def schema_from_xml(path):
    root = ET.parse(path).getroot()
    parameters = []
    for group in root.findall('./ParameterSets/ParameterSet'):
        for item in group.findall('Parameter'):
            parameters.append({'group': group.get('name'), **item.attrib})
    messages = []
    for item in root.findall('./MIDIMessages/MIDIMessage'):
        messages.append({**item.attrib, 'bytes': [dict(b.attrib, mappings=[dict(p.attrib) for p in b]) for b in item.findall('byte')]})
    return {'source': str(path.name), 'sourceSHA256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'parameters': parameters, 'messages': messages,
            'valueLists': [{**v.attrib, 'entries': [{**e.attrib, 'text': e.text} for e in v.findall('Entry')]} for v in root.findall('./Valuelists/Valuelist')]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('installer_tree', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    resources = args.installer_tree / 'Core_components.pkg/Payload/Library/Application Support/Access Music/Virus TI/Common/Virus Control.bundle/Contents/Resources'
    schema = schema_from_xml(resources / 'remotedevice.xml')
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'parameter-schema.json').write_text(json.dumps(schema, ensure_ascii=False, indent=2), encoding='utf-8')
    catalogue, errors, counts = [], [], {}
    audition_frames = bytearray()
    patches = args.installer_tree / 'Additional_items.pkg/Payload/Library/Application Support/Access Music/Virus TI/Patches'
    for file in sorted(patches.rglob('*.mid')):
        relative = str(file.relative_to(patches))
        try:
            for frame in smf_sysex(file.read_bytes()):
                preset = decode_single(frame)
                if preset:
                    catalogue.append({'file': relative, **preset})
                    if relative.startswith('Virus TI Snow Factory Backup/') and len(frame) == 524:
                        audition_frames.extend(frame)
                    else:
                        audition_frames.extend(bytes(524))
                    counts[preset['format']] = counts.get(preset['format'], 0) + 1
        except (ValueError, UnicodeDecodeError) as error:
            errors.append({'file': relative, 'error': str(error)})
    report = {'presetCount': len(catalogue), 'formatCounts': counts, 'parameters': len(schema['parameters']),
              'messageDefinitions': len(schema['messages']), 'valueLists': len(schema['valueLists']), 'errors': errors}
    (args.output / 'factory-presets.json').write_text(json.dumps(catalogue, ensure_ascii=False, indent=2), encoding='utf-8')
    (args.output / 'factory-audition.bin').write_bytes(audition_frames)
    (args.output / 'extraction-result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    if errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
