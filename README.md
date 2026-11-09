# Virus TI Snow Editor

An independent macOS editor and preset browser for the **Access Virus TI Snow**. This is a source preview for hardware testing. It is unaffiliated with Access Music and Kemper.

The editor reads the Snow's Single edit buffer over direct USB, follows supported front-panel changes, and verifies supported edits by reading the buffer back. It can import the 512 stored Single sounds from Snow RAM for browsing and auditioning. Audition replaces the current edit buffer.

## Install the release DMG

Download `Virus-TI-Snow-Editor-0.7.2-arm64.dmg` from Releases and mount it. You need an Apple Silicon Mac with macOS 13 or later, Python 3.9 or later, and your own copy of the Access Virus TI Software Suite 5.1.7.00 macOS installer. See [Access Music downloads](https://www.virus.info/downloads).

```sh
sh "/Volumes/Virus TI Snow Editor 0.7.2/Install.sh" "/path/to/Access installer.pkg"
open "$HOME/Applications/VirusTIBrowser.app"
```

The DMG contains the compiled editor and USB helper. Setup adds the assets from your installer, including the original Virus Control Center icon, to a local app without running the installer or installing a driver. To choose another location or keep an existing installation, pass a new `.app` path as the second argument. This testing release is ad-hoc signed and has not been notarized by Apple.

## Build on macOS

You need an Apple Silicon Mac running macOS 13 or later, Xcode Command Line Tools, Python 3.9 or later, and a local copy of the Access macOS Virus TI installer. The tested installer layout is from version **5.1.7.00**. See [Access Music downloads](https://www.virus.info/downloads).

Install the command-line tools if needed:

```sh
xcode-select --install
```

From this repository, run:

```sh
./prepare-assets.sh "/path/to/Virus TI installer.pkg"
./build-browser.sh
open build/VirusTIBrowser.app
```

If your download is a disk image, mount it and pass the installer package inside it. You can also pass an already expanded installer directory containing `Core_components.pkg` and `Additional_items.pkg`. The asset script extracts files locally without running the installer or loading the original plug-in. It generates the original layout and artwork, factory catalogue, and edit mappings for your build. Keep those generated files and the locally built app out of public uploads.

## First hardware test

1. Put the Snow in **Single mode**, connect it over USB, and open the app. The editor reads the active sound, enables **Follow Snow**, and starts importing the RAM catalogue. You can cancel the RAM read to start editing sooner.
2. Click **Read current sound** to refresh the edit buffer. Check that the displayed patch name matches the Snow and the status reports verified checksums.
3. Uncheck **Live**, move Filter 1 Cutoff slightly, then click **Apply change**. Check for verified readback. Click **Undo last edit** to restore the previous cutoff.
4. Turn the hardware cutoff knob, then select a different Single on the Snow. Confirm that the editor follows both actions.
5. To try the browser, export the current edit buffer first if you want to keep it. Select a Snow preset in **Browser** and click **Load into current sound**. Check the result in the editor's status line.

## What to report

- Mac model, macOS version, Snow firmware, and which mode the Snow was in.
- The page, control, and steps that reproduce the issue. Include the editor's status text.
- Whether the problem occurs on the Snow, in the editor, or in both. Use a factory patch name if it reproduces there.

Please keep private presets, RAM dumps, serial numbers, and personal file paths out of public reports.

## Preview limits

- Direct USB editing and Follow Snow have been tested in **Single mode**. The separate CoreMIDI path requires a compatible **Virus TI USB Plugin I/O** endpoint. Multi-part editing needs more hardware testing.
- Direct USB needs exclusive access to the Snow's USB MIDI interface. If the editor reports that it cannot open the interface, close other editors and check whether a MIDI driver owns it.
- Some controls are read-only or unavailable in the current mode. Soft knobs assigned to MIDI controllers show a position once the Snow sends a value.
- This preview edits the current buffer. Writing stored RAM slots, bulk restore, USB audio, and DAW integration are outside this build.

## Offline checks

Run these after building. They do not send MIDI:

```sh
build/VirusTIBrowser.app/Contents/MacOS/virus-identity-probe --self-test
build/VirusTIBrowser.app/Contents/MacOS/VirusTIBrowser --self-test
xcrun swiftc -target arm64-apple-macosx13.0 -parse-as-library \
  LiveEditSession.swift LiveSessionChecks.swift -o build/live-session-checks
build/live-session-checks "$PWD/tests/live_echo.py"
```

The repository contains the editor source, local extraction tools, and offline checks. A project license has yet to be selected. Access artwork, presets, installer files, and generated resources come from your local installer.
