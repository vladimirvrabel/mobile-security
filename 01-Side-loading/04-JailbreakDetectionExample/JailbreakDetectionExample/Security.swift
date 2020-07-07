//BSD 2-Clause License
//
//Copyright (c) 2019, SecuRing spółka z ograniczoną odpowiedzialnością spółka komandytowa
//Copyright (c) 2020 Vladimir Vrabel,

import Foundation

class Security {
    @inlinable static public func isDeviceJailbreaked() -> Bool {
        let disabledPaths = [
            // cydia
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/CydiaSubstrate.dylib",
            "/private/var/lib/cydia",
            "/private/var/tmp/cydia.log",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/usr/libexec/cydia/firmware.sh",
            "/var/lib/cydia",

            // electra
            "/etc/apt/sources.list.d/electra.list",
            "/etc/apt/sources.list.d/sileo.sources",
            "/jb/lzma",
            "/usr/lib/libjailbreak.dylib",
            "/.bootstrapped_electra",

            // frida
            "/usr/sbin/frida-server",

            // MobileSubstrate
            "/Library/MobileSubstrate/CydiaSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/var/lib/dpkg/info/mobilesubstrate.md5sums",

            // unc0ver
            "/etc/apt/undecimus/undecimus.list",
            "/jb/amfid_payload.dylib",
            "/jb/jailbreakd.plist",
            "/jb/libjailbreak.dylib",
            "/jb/offsets.plist",
            "/usr/share/jailbreak/injectme.plist",
            "/.cydia_no_stash",
            "/.installed_unc0ver"
        ]

        for path in disabledPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }

        return false
    }

    @inlinable static public func isWriteableOutsideOfSandbox() -> Bool {
        let paths = [
            "/",
            "/private/",
            "/root/"
        ]

        for path in paths {
            do {
                let fullPath = path + UUID().uuidString
                // create & write into test file
                try "test".write(toFile: fullPath, atomically: true, encoding: String.Encoding.utf8)
                // remove test file
                try FileManager.default.removeItem(atPath: fullPath)

                return true
            }
            catch {
                // nothing, because it is normal to not write outside of sandbox
            }
        }

        return false
    }
}
