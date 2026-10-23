"""Package source-built Vitrine components and generate matching AltStore metadata.

The Spotify base is the same hash-pinned community package used for the previous
working installation. This does not authenticate its proprietary executable.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import zipfile
from datetime import datetime, timezone

ROOT = "Payload/Spotify.app/"
BASE_SHA = "937ae1f258f8586e49c1e85399c327b910e4bbb6964a91f6433ac1bb863262e5"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fix_substrate(data):
    original = b"/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"
    replacement = b"@loader_path/CydiaSubstrate.framework/CydiaSubstrate"
    patched = bytearray(data)
    magic, _, _, _, count, size, _, _ = struct.unpack_from("<IiiIIIII", data)
    if magic != 0xFEEDFACF:
        raise ValueError("Expected a thin 64-bit Vitrine library")
    offset, changed = 32, 0
    for _ in range(count):
        command, length = struct.unpack_from("<II", data, offset)
        if length < 8 or offset + length > 32 + size:
            raise ValueError("Invalid Mach-O load command")
        if command in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023):
            name_offset = struct.unpack_from("<I", data, offset + 8)[0]
            start, end = offset + name_offset, offset + length
            name = data[start:end].split(b"\0", 1)[0]
            if name == original:
                assert len(replacement) + 1 <= end - start
                patched[start:end] = (replacement + b"\0").ljust(end - start, b"\0")
                changed += 1
        offset += length
    assert offset == 32 + size
    if changed != 1 and replacement not in patched:
        raise ValueError("Expected the previously verified Substrate dependency")
    return bytes(patched)


def package(base_path, components, output_dir, repository, mod_version, build_number):
    assert digest(base_path.read_bytes()) == BASE_SHA, "Spotify base hash mismatch"
    output_dir.mkdir(parents=True, exist_ok=True)
    provenance = json.loads((components / "build-provenance.json").read_text())
    assert provenance["debug_driver_enabled"] is False
    for name, expected in provenance["sha256"].items():
        assert digest((components / name).read_bytes()) == expected, name
    replacements = {}
    for name in ("spotifyglass.dylib", "SpotifyGlassAppGroups.dylib"):
        data = (components / name).read_bytes()
        replacements[ROOT + "Frameworks/" + name] = fix_substrate(data) if name == "spotifyglass.dylib" else data
    extension = components / "extension/SpotifyGlassLiveActivity.appex"
    target = ROOT + "PlugIns/SpotifyGlassLiveActivity.appex/"
    for path in extension.rglob("*"):
        if path.is_file() and "_CodeSignature" not in path.parts:
            replacements[target + path.relative_to(extension).as_posix()] = path.read_bytes()
    with zipfile.ZipFile(base_path) as base:
        assert base.testzip() is None
        app = plistlib.loads(base.read(ROOT + "Info.plist"))
        assert app["CFBundleIdentifier"] == "com.spotify.client"
        assert app["CFBundleShortVersionString"] == "9.1.90"
        original_executable = digest(base.read(ROOT + app["CFBundleExecutable"]))
        app["CFBundleVersion"] = build_number
        app["VitrineVersion"] = mod_version
        replacements[ROOT + "Info.plist"] = plistlib.dumps(app, fmt=plistlib.FMT_BINARY)
        for name in base.namelist():
            if name.startswith(ROOT + "PlugIns/") and name.endswith("/Info.plist") and name.count("/") == 4 and name not in replacements:
                info = plistlib.loads(base.read(name))
                info["CFBundleVersion"] = build_number
                replacements[name] = plistlib.dumps(info, fmt=plistlib.FMT_BINARY)
        info = plistlib.loads(replacements[target + "Info.plist"])
        assert info["CFBundleVersion"] == build_number
        metadata_name = ROOT + "Metadata.appintents/extract.actionsdata"
        metadata = json.loads(base.read(metadata_name))
        new_metadata = json.loads((components / "extension/app/Metadata.appintents/extract.actionsdata").read_text())
        for key, mine in new_metadata.items():
            theirs = metadata.get(key)
            if isinstance(mine, dict) and isinstance(theirs, dict):
                metadata[key] = {**theirs, **mine}
            elif isinstance(mine, list) and isinstance(theirs, list):
                def identity(item):
                    return (item.get("identifier") or item.get("actionIdentifier") or json.dumps(item, sort_keys=True)) if isinstance(item, dict) else json.dumps(item, sort_keys=True)
                new_ids = {identity(item) for item in mine}
                metadata[key] = [item for item in theirs if identity(item) not in new_ids] + mine
            elif theirs is None:
                metadata[key] = mine
        replacements[metadata_name] = json.dumps(metadata, separators=(",", ":")).encode()
        filename = f"Spotify-Vitrine-{mod_version}.ipa"
        ipa = output_dir / filename
        written, preserved = set(), {}
        with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
            for entry in base.infolist():
                name = entry.filename
                assert not name.startswith(("/", "\\")) and ".." not in name.split("/")
                assert name not in written
                if "/_CodeSignature/" in name or name.endswith("/embedded.mobileprovision"):
                    continue
                if name.startswith(target) and name not in replacements:
                    continue
                data = replacements.get(name)
                if data is None:
                    data = base.read(name)
                    preserved[name] = digest(data)
                output.writestr(entry, data)
                written.add(name)
            for name, data in replacements.items():
                if name not in written:
                    entry = zipfile.ZipInfo(name)
                    entry.create_system = 3
                    entry.external_attr = (0o100755 if name.endswith((".dylib", "/SpotifyGlassLiveActivity")) else 0o100644) << 16
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    output.writestr(entry, data)
    with zipfile.ZipFile(ipa) as output:
        assert output.testzip() is None
        assert len(output.namelist()) == len(set(output.namelist()))
        assert digest(output.read(ROOT + app["CFBundleExecutable"])) == original_executable
        assert ROOT + "Frameworks/CydiaSubstrate.framework/CydiaSubstrate" in output.namelist()
        for name, expected in preserved.items():
            assert digest(output.read(name)) == expected, name
        privacy, entitlements = {}, set()
        check_dir = output_dir / "permission-scan"
        check_dir.mkdir(exist_ok=True)
        bundle_infos = [ROOT + "Info.plist"] + [n for n in output.namelist() if n.startswith(ROOT + "PlugIns/") and n.endswith("/Info.plist") and n.count("/") == 4]
        for index, name in enumerate(bundle_infos):
            info = plistlib.loads(output.read(name))
            privacy.update({k: v for k, v in info.items() if "UsageDescription" in k and isinstance(v, str)})
            executable = name.rsplit("/", 1)[0] + "/" + info["CFBundleExecutable"]
            scan_file = check_dir / str(index)
            scan_file.write_bytes(output.read(executable))
            result = subprocess.run(["ldid", "-e", str(scan_file)], check=True, capture_output=True)
            if result.stdout.strip():
                entitlements.update(plistlib.loads(result.stdout))
            scan_file.unlink()
        check_dir.rmdir()
    tag = f"spotify-vitrine-{mod_version}"
    version = {
        "version": app["CFBundleShortVersionString"], "buildVersion": build_number,
        "marketingVersion": f"Spotify {app['CFBundleShortVersionString']} / Vitrine {mod_version}",
        "date": datetime.now(timezone.utc).isoformat(),
        "localizedDescription": f"Vitrine {mod_version}, built from pinned source. Includes the Live Activity for lyrics and the sideload library-path fix. Sign with the same Apple account as your existing Spotify installation.",
        "downloadURL": f"https://github.com/{repository}/releases/download/{tag}/{filename}",
        "size": ipa.stat().st_size, "minOSVersion": app["MinimumOSVersion"],
    }
    source = {
        "name": "Egzon's Apps", "identifier": "com.egzon.altstore.source",
        "subtitle": "Personal AltStore builds", "website": f"https://github.com/{repository}",
        "iconURL": f"https://raw.githubusercontent.com/{repository}/main/icons/Vitrine.png",
        "tintColor": "#1DB954", "apps": [{
            "name": "Spotify + Vitrine", "bundleIdentifier": app["CFBundleIdentifier"],
            "developerName": "Spotify / Vitrine contributors",
            "localizedDescription": "Spotify with Vitrine's interface and lyrics features. Personal unsigned build; AltStore signs it for your device. Not affiliated with Spotify.",
            "iconURL": f"https://raw.githubusercontent.com/{repository}/main/icons/Vitrine.png",
            "tintColor": "#1DB954", "category": "entertainment", "versions": [version],
            "appPermissions": {"entitlements": sorted(entitlements), "privacy": privacy},
        }], "news": [],
    }
    (output_dir / "altstore-source.json").write_text(json.dumps(source, indent=2) + "\n")
    report = {**provenance, "spotify_base_sha256": BASE_SHA,
              "spotify_executable_sha256": original_executable,
              "spotify_executable_verified_as_official": False,
              "ipa_sha256": digest(ipa.read_bytes()), "ipa_size": ipa.stat().st_size,
              "vitrine_version": mod_version, "build_number": build_number,
              "substrate_dependency": "@loader_path/CydiaSubstrate.framework/CydiaSubstrate",
              "signing": "Unsigned; requires AltStore signing", "release_tag": tag}
    (output_dir / "build-details.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"ipa": str(ipa), "sha256": report["ipa_sha256"], "build_number": build_number}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path)
    parser.add_argument("components", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "egzonkurtishi01-jpg/vitrine"))
    parser.add_argument("--version", default="1.0.0-beta.14")
    parser.add_argument("--build-number", default="919002270")
    args = parser.parse_args()
    package(args.base, args.components, args.output, args.repository, args.version, args.build_number)
