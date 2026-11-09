#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s /path/to/Access-installer.pkg-or-expanded-folder\n' "$0" >&2
    exit 2
fi

case "$1" in
    /*) installer="$1" ;;
    *) installer="$PWD/$1" ;;
esac

cd "$(dirname "$0")"
if [ -f "$installer" ]; then
    scratch="$(mktemp -d)"
    trap 'rm -rf "$scratch"' EXIT
    /usr/sbin/pkgutil --expand-full "$installer" "$scratch/expanded"
    installer="$scratch/expanded"
fi

resources="$installer/Core_components.pkg/Payload/Library/Application Support/Access Music/Virus TI/Common/Virus Control.bundle/Contents/Resources"
for file in editorPR.xml remotedevicePR.xml editordevice.xml remotedevice.xml; do
    if [ ! -f "$resources/$file" ]; then
        printf 'Missing %s. Use the expanded macOS Virus TI installer containing Core_components.pkg and Additional_items.pkg.\n' "$file" >&2
        exit 1
    fi
done

python3 extract_original_ui.py "$installer" original-ui
python3 preset_tools.py "$installer" catalog
python3 generate_editable.py

icon="$installer/Core_components.pkg/Payload/Applications/Access Music/Virus TI/Virus Control Center.app/Contents/Resources/VCC.icns"
if [ ! -f "$icon" ]; then
    printf 'Missing the Virus Control Center icon. Use the Access 5.1.7.00 installer.\n' >&2
    exit 1
fi
cp "$icon" catalog/VCC.icns
