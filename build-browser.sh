#!/bin/sh
set -eu
cd "$(dirname "$0")"
app_path="${1:-build/VirusTIBrowser.app}"
for resource in original-ui/layout.json catalog/parameter-schema.json catalog/factory-presets.json catalog/factory-audition.bin catalog/VCC.icns editable-parameters.json EditableParameters.h; do
    if [ ! -f "$resource" ]; then
        printf 'Missing %s. Run ./prepare-assets.sh with your Access installer first.\n' "$resource" >&2
        exit 1
    fi
done
mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources"
xcrun clang -target arm64-apple-macos13.0 -fobjc-arc -fblocks IdentityProbe.m SnowUSB.c -o "$app_path/Contents/MacOS/virus-identity-probe" -framework Foundation -framework CoreMIDI -framework IOKit -framework CoreFoundation
xcrun swiftc -target arm64-apple-macosx13.0 -module-cache-path /tmp/virus-swift-cache -parse-as-library Browser.swift EditableParameter.swift LiveEditSession.swift OriginalInterface.swift -o "$app_path/Contents/MacOS/VirusTIBrowser" -framework SwiftUI -framework AppKit
cp catalog/parameter-schema.json catalog/factory-presets.json catalog/factory-audition.bin catalog/VCC.icns "$app_path/Contents/Resources/"
cp editable-parameters.json "$app_path/Contents/Resources/"
rm -f "$app_path/Contents/Resources/verified-preset.json"
mkdir -p "$app_path/Contents/Resources/original-ui"
cp original-ui/* "$app_path/Contents/Resources/original-ui/"
cat > "$app_path/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>local.virusti.browser.preview072</string>
<key>CFBundleName</key><string>Virus TI Browser</string>
<key>CFBundleDisplayName</key><string>Virus TI Browser 0.7.2</string>
<key>CFBundleExecutable</key><string>VirusTIBrowser</string>
<key>CFBundleIconFile</key><string>VCC.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.7.2</string>
<key>CFBundleVersion</key><string>9</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$app_path/Contents/MacOS/virus-identity-probe"
codesign --force --sign - "$app_path"
codesign --verify --deep --strict "$app_path"
