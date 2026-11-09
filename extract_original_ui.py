"""Extract the user's supplied Virus Control Snow UI without running its code."""
from pathlib import Path
import json
import shutil
import sys
import xml.etree.ElementTree as ET

root = Path(sys.argv[1]) / 'Core_components.pkg/Payload/Library/Application Support/Access Music/Virus TI/Common/Virus Control.bundle/Contents/Resources'
out = Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
editor = ET.parse(root / 'editorPR.xml').getroot()

def node(element):
    size = element.find('Size')
    return {'type': element.tag, 'attributes': dict(element.attrib),
            'size': dict(size.attrib) if size is not None else {},
            'foreground': dict(element.find('ForeColor').attrib) if element.find('ForeColor') is not None else {},
            'children': [node(c) for c in element if c.find('Size') is not None]}

defaults, parameters, conditions, lists = {}, {}, {}, {}
for filename in ['remotedevicePR.xml', 'editordevice.xml']:
    document = ET.parse(root / filename).getroot()
    for group in document.findall('./ParameterSets/ParameterSet'):
        for parameter in group.findall('Parameter'):
            path = group.get('name') + '/' + parameter.get('name')
            parameters[path] = dict(parameter.attrib)
            try: defaults[path] = int(parameter.get('defaultValue', '0'))
            except ValueError: pass
    for condition in document.findall('./Conditionsets/Condition'):
        conditions[condition.get('name')] = {**condition.attrib, 'tests': [dict(t.attrib) for t in condition]}
    for values in document.findall('./Valuelists/Valuelist'):
        lists[values.get('name')] = {e.get('index'): e.text for e in values.findall('Entry')}

images = set()
for element in editor.iter():
    for value in element.attrib.values():
        if value.lower().endswith('.png'): images.add(value)
missing = []
for filename in sorted(images):
    source = root / filename
    if source.is_file(): shutil.copy2(source, out / filename)
    else: missing.append(filename)
frame = editor.find('Frame')
data = {'width': int(frame.get('width')), 'height': int(frame.get('height')),
        'frame': node(frame), 'defaults': defaults, 'parameters': parameters,
        'conditions': conditions, 'valueLists': lists,
        'source': 'editorPR.xml (original four-part Snow layout)', 'missingImages': missing}
(out / 'layout.json').write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
print(json.dumps({'images': len(images)-len(missing), 'conditions': len(conditions), 'parameters': len(parameters), 'missingImages': missing}))
