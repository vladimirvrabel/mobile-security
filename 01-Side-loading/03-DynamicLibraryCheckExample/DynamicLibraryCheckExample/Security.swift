//BSD 2-Clause License
//
//Copyright (c) 2019, SecuRing spółka z ograniczoną odpowiedzialnością spółka komandytowa
//Copyright (c) 2020 Vladimir Vrabel,

import Foundation
import MachO

class Security {
    @inlinable static public func areUnsupportedDynamicLibsLoaded() -> Bool {
        let unsupportedLibNames = [
            "cynject", // Substrate
            "MobileSubstrate",
            "frida",
            "FridaGadget",
            "libcycript",
            "SSLKillSwitch",
            "SubstrateLoader"
        ]

        for i in 0..<_dyld_image_count() {
            guard let loadedLibrary = String(validatingUTF8: _dyld_get_image_name(i)) else {
                continue
            }

            for name in unsupportedLibNames {
                if loadedLibrary.lowercased().contains(name.lowercased()) {
                    return true
                }
            }
        }

        return false
    }
}
