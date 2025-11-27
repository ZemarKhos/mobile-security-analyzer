"""
Frida Script Templates Library
Pre-built bypass scripts for common Android and iOS security mechanisms

Enhanced with advanced bypass techniques including:
- KernelSU detection bypass
- Emulator detection bypass
- Native-level (libc.so) bypasses
- Flutter SSL pinning bypass
- Dynamic SSLPeerUnverifiedException auto-patcher
- HTTP traffic interception
- 30+ third-party library bypasses
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class BypassCategory(str, Enum):
    ROOT_DETECTION = "root_detection"
    SSL_PINNING = "ssl_pinning"
    ANTI_TAMPERING = "anti_tampering"
    ANTI_DEBUG = "anti_debug"
    EMULATOR_DETECTION = "emulator_detection"
    JAILBREAK_DETECTION = "jailbreak_detection"
    TRAFFIC_INTERCEPTION = "traffic_interception"
    FLUTTER_BYPASS = "flutter_bypass"


@dataclass
class FridaTemplate:
    """A single Frida bypass template"""
    id: str
    name: str
    category: BypassCategory
    platform: str  # "android", "ios", or "both"
    description: str
    targets: List[str]  # Classes/methods this bypasses
    script: str
    difficulty: str  # "easy", "medium", "hard"


# ============================================
# ANDROID ROOT DETECTION BYPASS SCRIPTS
# ============================================

ANDROID_ROOT_GENERIC = '''
/**
 * Advanced Root Detection Bypass
 * Comprehensive bypass including KernelSU, Magisk, SuperSU and all common root paths
 * Includes Java-level and Native-level bypasses
 */

Java.perform(function() {
    console.log("[*] Starting Advanced Root Detection Bypass...");

    // ===== Comprehensive Root Paths (including KernelSU) =====
    var rootPaths = [
        "/data/local/bin/su",
        "/data/local/su",
        "/data/local/xbin/su",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/sbin/su",
        "/system/app/Superuser.apk",
        "/system/bin/failsafe/su",
        "/system/bin/su",
        "/system/etc/init.d/99telecominfomern",
        "/system/sd/xbin/su",
        "/su/bin/su",
        "/system/xbin/busybox",
        "/system/xbin/daemonsu",
        "/system/xbin/su",
        "/system/sbin/su",
        "/vendor/bin/su",
        "/cache/su",
        "/data/su",
        "/dev/su",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/system/xbin/mu",
        "/system/app/Kinguser.apk",
        "/data/adb/magisk",
        "/sbin/.magisk",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock",
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/data/adb/ksu/bin",
        "/data/adb/ksu/bin/su",
        "/data/adb/ksu/bin/ksud",
        "/sbin/.core",
        "/debug_ramdisk",
        "/system/xbin/bstk/su",
        "/data/adbroot",
        "/magisk/.core/bin",
        "/data/magisk",
        "/data/adb/modules",
        "/data/user_de/0/com.topjohnwu.magisk"
    ];

    // ===== Root Management Apps (including KernelSU) =====
    var rootManagementApps = [
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclean",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
        "me.weishu.kernelsu",
        "com.formyhm.hideroot",
        "com.saurik.substrate",
        "de.robv.android.xposed.installer"
    ];

    // ===== File.exists() Bypass =====
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) !== -1) {
                console.log("[+] Root bypass (File.exists): " + path);
                return false;
            }
        }
        // Also check for su, magisk, kernelsu keywords
        var keywords = ["su", "magisk", "kernelsu", "ksu", "superuser", "busybox", "xposed"];
        for (var j = 0; j < keywords.length; j++) {
            if (path.toLowerCase().indexOf(keywords[j]) !== -1) {
                console.log("[+] Root bypass (keyword): " + path);
                return false;
            }
        }
        return this.exists.call(this);
    };

    // ===== File.isDirectory() Bypass =====
    File.isDirectory.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) !== -1) {
                console.log("[+] Root bypass (File.isDirectory): " + path);
                return false;
            }
        }
        return this.isDirectory.call(this);
    };

    // ===== Unix File System Native Bypass =====
    try {
        var UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            var path = file.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++) {
                if (path.indexOf(rootPaths[i]) !== -1) {
                    console.log("[+] Root bypass (UnixFileSystem.checkAccess): " + path);
                    return false;
                }
            }
            return this.checkAccess(file, access);
        };
    } catch(e) {
        console.log("[-] UnixFileSystem not found");
    }

    // ===== Runtime.exec() Bypass (all overloads) =====
    var Runtime = Java.use("java.lang.Runtime");

    var execCommands = ["su", "which", "busybox", "magisk", "ksu", "kernelsu", "/su"];

    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        for (var i = 0; i < execCommands.length; i++) {
            if (cmd.indexOf(execCommands[i]) !== -1) {
                console.log("[+] Root bypass (Runtime.exec): " + cmd);
                throw Java.use("java.io.IOException").$new("Permission denied");
            }
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmds) {
        var cmdStr = cmds.join(" ");
        for (var i = 0; i < execCommands.length; i++) {
            if (cmdStr.indexOf(execCommands[i]) !== -1) {
                console.log("[+] Root bypass (Runtime.exec[]): " + cmdStr);
                throw Java.use("java.io.IOException").$new("Permission denied");
            }
        }
        return this.exec(cmds);
    };

    // ===== ProcessBuilder Bypass =====
    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function() {
            var cmds = this.command().toArray();
            var cmdStr = cmds.join(" ");
            for (var i = 0; i < execCommands.length; i++) {
                if (cmdStr.indexOf(execCommands[i]) !== -1) {
                    console.log("[+] Root bypass (ProcessBuilder): " + cmdStr);
                    throw Java.use("java.io.IOException").$new("Permission denied");
                }
            }
            return this.start();
        };
    } catch(e) {
        console.log("[-] ProcessBuilder hook failed");
    }

    // ===== System Properties Bypass =====
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");

        SystemProperties.get.overload("java.lang.String").implementation = function(key) {
            if (key === "ro.debuggable" || key === "ro.build.selinux") {
                console.log("[+] Root bypass (SystemProperties): " + key);
                return "0";
            }
            if (key === "ro.secure") {
                return "1";
            }
            return this.get(key);
        };

        SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function(key, def) {
            if (key === "ro.debuggable" || key === "ro.build.selinux") {
                console.log("[+] Root bypass (SystemProperties): " + key);
                return "0";
            }
            if (key === "ro.secure") {
                return "1";
            }
            return this.get(key, def);
        };
    } catch(e) {
        console.log("[-] SystemProperties hook failed");
    }

    // ===== Build Properties Bypass =====
    var Build = Java.use("android.os.Build");
    var tags = Build.TAGS.value;
    if (tags != null && tags.indexOf("test-keys") !== -1) {
        Build.TAGS.value = "release-keys";
        console.log("[+] Bypassed Build.TAGS");
    }

    // ===== Package Manager Bypass =====
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkg, flags) {
            for (var i = 0; i < rootManagementApps.length; i++) {
                if (pkg === rootManagementApps[i]) {
                    console.log("[+] Hiding root app: " + pkg);
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                }
            }
            return this.getPackageInfo(pkg, flags);
        };
    } catch(e) {
        console.log("[-] PackageManager hook failed");
    }

    console.log("[*] Advanced Root Detection Bypass Active");
    console.log("[*] Monitoring: " + rootPaths.length + " paths, " + rootManagementApps.length + " apps");
});
'''

ANDROID_ROOTBEER_BYPASS = '''
/**
 * RootBeer Library Bypass
 * Targets: com.scottyab.rootbeer
 */

Java.perform(function() {
    console.log("[*] Starting RootBeer Bypass...");

    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");

        RootBeer.isRooted.implementation = function() {
            console.log("[+] Bypassed RootBeer.isRooted()");
            return false;
        };

        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log("[+] Bypassed RootBeer.isRootedWithoutBusyBoxCheck()");
            return false;
        };

        RootBeer.detectRootManagementApps.implementation = function() {
            console.log("[+] Bypassed RootBeer.detectRootManagementApps()");
            return false;
        };

        RootBeer.detectPotentiallyDangerousApps.implementation = function() {
            console.log("[+] Bypassed RootBeer.detectPotentiallyDangerousApps()");
            return false;
        };

        RootBeer.detectTestKeys.implementation = function() {
            console.log("[+] Bypassed RootBeer.detectTestKeys()");
            return false;
        };

        RootBeer.checkForBusyBoxBinary.implementation = function() {
            console.log("[+] Bypassed RootBeer.checkForBusyBoxBinary()");
            return false;
        };

        RootBeer.checkForSuBinary.implementation = function() {
            console.log("[+] Bypassed RootBeer.checkForSuBinary()");
            return false;
        };

        RootBeer.checkSuExists.implementation = function() {
            console.log("[+] Bypassed RootBeer.checkSuExists()");
            return false;
        };

        RootBeer.checkForRWPaths.implementation = function() {
            console.log("[+] Bypassed RootBeer.checkForRWPaths()");
            return false;
        };

        RootBeer.checkForDangerousProps.implementation = function() {
            console.log("[+] Bypassed RootBeer.checkForDangerousProps()");
            return false;
        };

        RootBeer.checkForRootNative.implementation = function() {
            console.log("[+] Bypassed RootBeer.checkForRootNative()");
            return false;
        };

        RootBeer.detectRootCloakingApps.implementation = function() {
            console.log("[+] Bypassed RootBeer.detectRootCloakingApps()");
            return false;
        };

        RootBeer.checkForMagiskBinary.implementation = function() {
            console.log("[+] Bypassed RootBeer.checkForMagiskBinary()");
            return false;
        };

        console.log("[*] RootBeer Bypass Active");
    } catch (e) {
        console.log("[-] RootBeer not found: " + e);
    }
});
'''

ANDROID_MAGISK_BYPASS = '''
/**
 * Magisk Detection Bypass
 * Hides Magisk presence from apps
 */

Java.perform(function() {
    console.log("[*] Starting Magisk Detection Bypass...");

    // Hide Magisk Manager package
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkg, flags) {
        var magiskPackages = [
            "com.topjohnwu.magisk",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.formyhm.hideroot",
            "com.koushikdutta.superuser",
            "eu.chainfire.supersu"
        ];

        for (var i = 0; i < magiskPackages.length; i++) {
            if (pkg.indexOf(magiskPackages[i]) !== -1) {
                console.log("[+] Hiding package: " + pkg);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
            }
        }
        return this.getPackageInfo(pkg, flags);
    };

    // Hide Magisk mount points
    var BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.overload().implementation = function() {
        var line = this.readLine();
        if (line != null) {
            if (line.indexOf("magisk") !== -1 || line.indexOf("/sbin/.core") !== -1) {
                console.log("[+] Hiding mount line: " + line);
                return this.readLine();
            }
        }
        return line;
    };

    console.log("[*] Magisk Detection Bypass Active");
});
'''

# ============================================
# ANDROID EMULATOR DETECTION BYPASS
# ============================================

ANDROID_EMULATOR_BYPASS = '''
/**
 * Emulator Detection Bypass
 * Spoofs Build properties to hide emulator environment
 * Bypasses common emulator detection techniques
 */

Java.perform(function() {
    console.log("[*] Starting Emulator Detection Bypass...");

    var Build = Java.use("android.os.Build");

    // Spoof device properties to look like a real device
    Build.FINGERPRINT.value = "google/sunfish/sunfish:11/RQ3A.210805.001.A1/7474174:user/release-keys";
    Build.MODEL.value = "Pixel 4a";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.DEVICE.value = "sunfish";
    Build.PRODUCT.value = "sunfish";
    Build.HARDWARE.value = "sunfish";
    Build.BOARD.value = "sunfish";
    Build.HOST.value = "abfarm-release-2004-0061";
    Build.TAGS.value = "release-keys";

    console.log("[+] Build properties spoofed");

    // System Properties bypass for emulator detection
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");

        var emulatorProps = {
            "ro.kernel.qemu": "0",
            "ro.hardware": "sunfish",
            "ro.product.model": "Pixel 4a",
            "ro.product.brand": "google",
            "ro.product.device": "sunfish",
            "ro.product.manufacturer": "Google",
            "ro.build.characteristics": "default",
            "ro.bootimage.build.fingerprint": "google/sunfish/sunfish:11/RQ3A.210805.001.A1/7474174:user/release-keys",
            "init.svc.qemu-props": "",
            "init.svc.goldfish-logcat": "",
            "init.svc.goldfish-setup": "",
            "ro.hardware.audio.primary": "sunfish",
            "ro.kernel.android.qemud": "",
            "ro.kernel.qemu.gles": ""
        };

        SystemProperties.get.overload("java.lang.String").implementation = function(key) {
            if (emulatorProps.hasOwnProperty(key)) {
                console.log("[+] Emulator bypass (SystemProperties): " + key);
                return emulatorProps[key];
            }
            return this.get(key);
        };

        SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function(key, def) {
            if (emulatorProps.hasOwnProperty(key)) {
                console.log("[+] Emulator bypass (SystemProperties): " + key);
                return emulatorProps[key];
            }
            return this.get(key, def);
        };
    } catch(e) {
        console.log("[-] SystemProperties hook failed: " + e);
    }

    // TelephonyManager bypass
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getDeviceId.overload().implementation = function() {
            console.log("[+] Emulator bypass (getDeviceId)");
            return "352693090123456";
        };

        TelephonyManager.getSubscriberId.implementation = function() {
            console.log("[+] Emulator bypass (getSubscriberId)");
            return "310260123456789";
        };

        TelephonyManager.getLine1Number.implementation = function() {
            console.log("[+] Emulator bypass (getLine1Number)");
            return "+1234567890";
        };

        TelephonyManager.getNetworkOperatorName.implementation = function() {
            console.log("[+] Emulator bypass (getNetworkOperatorName)");
            return "T-Mobile";
        };

        TelephonyManager.getSimOperatorName.implementation = function() {
            console.log("[+] Emulator bypass (getSimOperatorName)");
            return "T-Mobile";
        };

        TelephonyManager.getSimSerialNumber.implementation = function() {
            console.log("[+] Emulator bypass (getSimSerialNumber)");
            return "89014104123456789012";
        };
    } catch(e) {
        console.log("[-] TelephonyManager hook failed: " + e);
    }

    // SensorManager bypass (emulators often lack sensors)
    try {
        var SensorManager = Java.use("android.hardware.SensorManager");
        SensorManager.getSensorList.implementation = function(type) {
            var result = this.getSensorList(type);
            if (result.size() === 0) {
                console.log("[*] Emulator detection via empty sensor list, returning fake sensors");
            }
            return result;
        };
    } catch(e) {}

    // File check bypass for emulator-specific files
    var File = Java.use("java.io.File");
    var emulatorFiles = [
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/sys/qemu_trace",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/system/bin/qemu-props",
        "/dev/goldfish_pipe",
        "ueventd.android_x86.rc",
        "x86.prop",
        "ueventd.ttVM_x86.rc",
        "init.ttVM_x86.rc",
        "fstab.ttVM_x86",
        "fstab.vbox86",
        "init.vbox86.rc",
        "ueventd.vbox86.rc",
        "/dev/vboxguest",
        "/dev/vboxuser"
    ];

    var origExists = File.exists;
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < emulatorFiles.length; i++) {
            if (path.indexOf(emulatorFiles[i]) !== -1) {
                console.log("[+] Emulator bypass (file check): " + path);
                return false;
            }
        }
        return origExists.call(this);
    };

    console.log("[*] Emulator Detection Bypass Active");
});
'''

# ============================================
# ANDROID NATIVE LEVEL BYPASSES
# ============================================

ANDROID_NATIVE_BYPASS = '''
/**
 * Native Level Bypass (libc.so)
 * Hooks native functions: fopen, access, system
 * Provides low-level protection against root/file checks
 */

// Root paths to hide at native level
var nativeRootPaths = [
    "su", "magisk", "superuser", "busybox", "kernelsu", "ksu",
    "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/su",
    "/data/adb/ksu", "/data/adb/magisk"
];

// Hook fopen to hide root files
var fopen = Module.findExportByName("libc.so", "fopen");
if (fopen) {
    Interceptor.attach(fopen, {
        onEnter: function(args) {
            this.path = args[0].readCString();
        },
        onLeave: function(retval) {
            if (this.path) {
                for (var i = 0; i < nativeRootPaths.length; i++) {
                    if (this.path.indexOf(nativeRootPaths[i]) !== -1) {
                        console.log("[+] Native bypass (fopen): " + this.path);
                        retval.replace(ptr(0)); // Return NULL
                        return;
                    }
                }
            }
        }
    });
    console.log("[+] fopen hook installed");
}

// Hook access to hide root files
var access = Module.findExportByName("libc.so", "access");
if (access) {
    Interceptor.attach(access, {
        onEnter: function(args) {
            this.path = args[0].readCString();
        },
        onLeave: function(retval) {
            if (this.path) {
                for (var i = 0; i < nativeRootPaths.length; i++) {
                    if (this.path.indexOf(nativeRootPaths[i]) !== -1) {
                        console.log("[+] Native bypass (access): " + this.path);
                        retval.replace(-1); // Return -1 (file not accessible)
                        return;
                    }
                }
            }
        }
    });
    console.log("[+] access hook installed");
}

// Hook system to block root commands
var system_func = Module.findExportByName("libc.so", "system");
if (system_func) {
    Interceptor.attach(system_func, {
        onEnter: function(args) {
            var cmd = args[0].readCString();
            if (cmd) {
                for (var i = 0; i < nativeRootPaths.length; i++) {
                    if (cmd.indexOf(nativeRootPaths[i]) !== -1) {
                        console.log("[+] Native bypass (system): " + cmd);
                        args[0] = Memory.allocUtf8String("echo blocked");
                        return;
                    }
                }
            }
        }
    });
    console.log("[+] system hook installed");
}

// Hook stat/lstat for file existence checks
var stat = Module.findExportByName("libc.so", "stat");
if (stat) {
    Interceptor.attach(stat, {
        onEnter: function(args) {
            this.path = args[0].readCString();
        },
        onLeave: function(retval) {
            if (this.path) {
                for (var i = 0; i < nativeRootPaths.length; i++) {
                    if (this.path.indexOf(nativeRootPaths[i]) !== -1) {
                        console.log("[+] Native bypass (stat): " + this.path);
                        retval.replace(-1);
                        return;
                    }
                }
            }
        }
    });
    console.log("[+] stat hook installed");
}

// Hook strstr to bypass string-based root detection
var strstr = Module.findExportByName("libc.so", "strstr");
if (strstr) {
    Interceptor.attach(strstr, {
        onEnter: function(args) {
            this.needle = args[1].readCString();
        },
        onLeave: function(retval) {
            if (this.needle && !retval.isNull()) {
                var needleLower = this.needle.toLowerCase();
                if (needleLower.indexOf("su") !== -1 ||
                    needleLower.indexOf("magisk") !== -1 ||
                    needleLower.indexOf("root") !== -1) {
                    console.log("[+] Native bypass (strstr): " + this.needle);
                    retval.replace(ptr(0));
                }
            }
        }
    });
    console.log("[+] strstr hook installed");
}

console.log("[*] Native Level Bypass Active");
'''

# ============================================
# ANDROID SSL PINNING BYPASS SCRIPTS
# ============================================

ANDROID_SSL_UNIVERSAL = '''
/**
 * Universal SSL Pinning Bypass
 * Works with most SSL pinning implementations
 */

Java.perform(function() {
    console.log("[*] Starting Universal SSL Pinning Bypass...");

    // ===== TrustManager Bypass =====
    var TrustManager = Java.registerClass({
        name: "com.custom.TrustManager",
        implements: [Java.use("javax.net.ssl.X509TrustManager")],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var SSLContextInit = SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    );

    SSLContextInit.implementation = function(km, tm, sr) {
        console.log("[+] Bypassed SSLContext.init()");
        SSLContextInit.call(this, km, TrustManagers, sr);
    };

    // ===== OkHttp3 Bypass =====
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            console.log("[+] Bypassed OkHttp3 CertificatePinner for: " + hostname);
        };

        CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(hostname, peerCertificates) {
            console.log("[+] Bypassed OkHttp3 CertificatePinner for: " + hostname);
        };
    } catch (e) {
        console.log("[-] OkHttp3 not found");
    }

    // ===== Retrofit/OkHttp Bypass =====
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient$Builder");
        OkHttpClient.certificatePinner.implementation = function(certificatePinner) {
            console.log("[+] Bypassed OkHttpClient.certificatePinner()");
            return this;
        };
    } catch (e) {
        console.log("[-] OkHttpClient not found");
    }

    // ===== HttpsURLConnection Bypass =====
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[+] Bypassed HttpsURLConnection.setDefaultHostnameVerifier()");
        };

        HttpsURLConnection.setSSLSocketFactory.implementation = function(sslSocketFactory) {
            console.log("[+] Bypassed HttpsURLConnection.setSSLSocketFactory()");
        };

        HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[+] Bypassed HttpsURLConnection.setHostnameVerifier()");
        };
    } catch (e) {
        console.log("[-] HttpsURLConnection bypass error");
    }

    // ===== WebView SSL Error Bypass =====
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] Bypassed WebView SSL Error");
            handler.proceed();
        };
    } catch (e) {
        console.log("[-] WebViewClient not found");
    }

    // ===== TrustManagerImpl Bypass (Android 7+) =====
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function() {
            console.log("[+] Bypassed TrustManagerImpl.verifyChain()");
            return Java.use("java.util.ArrayList").$new();
        };
    } catch (e) {
        console.log("[-] TrustManagerImpl not found");
    }

    console.log("[*] Universal SSL Pinning Bypass Active");
});
'''

ANDROID_NETWORK_SECURITY_CONFIG = '''
/**
 * Network Security Config Bypass
 * For apps using Android's Network Security Configuration
 */

Java.perform(function() {
    console.log("[*] Starting Network Security Config Bypass...");

    try {
        // Bypass NetworkSecurityConfig
        var NetworkSecurityConfig = Java.use("android.security.net.config.NetworkSecurityConfig");
        NetworkSecurityConfig.isCleartextTrafficPermitted.overload().implementation = function() {
            console.log("[+] Bypassed NetworkSecurityConfig.isCleartextTrafficPermitted()");
            return true;
        };
    } catch (e) {
        console.log("[-] NetworkSecurityConfig not found");
    }

    try {
        // Bypass ManifestConfigSource
        var ManifestConfigSource = Java.use("android.security.net.config.ManifestConfigSource");
        ManifestConfigSource.getDefaultConfig.implementation = function() {
            console.log("[+] Bypassed ManifestConfigSource.getDefaultConfig()");
            var config = this.getDefaultConfig();
            return config;
        };
    } catch (e) {
        console.log("[-] ManifestConfigSource not found");
    }

    console.log("[*] Network Security Config Bypass Active");
});
'''

# ============================================
# MEGA SSL PINNING BYPASS (30+ LIBRARIES)
# ============================================

ANDROID_SSL_MEGA_BYPASS = '''
/**
 * MEGA SSL Pinning Bypass
 * Comprehensive bypass covering 30+ SSL pinning implementations
 * Includes dynamic SSLPeerUnverifiedException auto-patcher
 *
 * Covers:
 * - TrustManager (Android < 7 and > 7)
 * - OkHTTP v3 (quadruple bypass)
 * - Trustkit (triple bypass)
 * - Appcelerator, Fabric, PhoneGap
 * - IBM MobileFirst/WorkLight
 * - Conscrypt CertPinManager
 * - CWAC-Netsecurity
 * - Netty FingerprintTrustManagerFactory
 * - Squareup OkHTTP
 * - Apache Cordova
 * - Boye AbstractVerifier
 * - Appmattus CertificateTransparency
 * - Chromium Cronet
 * - And more...
 */

Java.perform(function() {
    console.log("[*] Starting MEGA SSL Pinning Bypass...");
    console.log("[*] Targeting 30+ SSL pinning implementations...");

    // ===== Dynamic SSLPeerUnverifiedException Auto-Patcher =====
    // Automatically patches any method that throws this exception
    try {
        var UnverifiedCertError = Java.use("javax.net.ssl.SSLPeerUnverifiedException");
        UnverifiedCertError.$init.implementation = function(reason) {
            console.log("[!] SSLPeerUnverifiedException intercepted: " + reason);

            try {
                var stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                var exceptionClass = stackTrace[4].getClassName();
                var exceptionMethod = stackTrace[4].getMethodName();

                console.log("[*] Auto-patching: " + exceptionClass + "." + exceptionMethod);

                var targetClass = Java.use(exceptionClass);
                var overloadCount = targetClass[exceptionMethod].overloads.length;

                for (var i = 0; i < overloadCount; i++) {
                    targetClass[exceptionMethod].overloads[i].implementation = function() {
                        console.log("[+] Auto-patched method bypassed");
                        return;
                    };
                }
            } catch(e) {
                console.log("[-] Auto-patch failed: " + e);
            }

            return this.$init(reason);
        };
        console.log("[+] SSLPeerUnverifiedException auto-patcher active");
    } catch(e) {
        console.log("[-] Auto-patcher setup failed");
    }

    // ===== Custom TrustManager =====
    var TrustManager = Java.registerClass({
        name: "com.mega.bypass.TrustManager",
        implements: [Java.use("javax.net.ssl.X509TrustManager")],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    // ===== TrustManagerImpl (Android < 7) =====
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManagers = [TrustManager.$new()];

        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function(km, tm, sr) {
            console.log("[+] SSLContext.init bypassed");
            this.init(km, TrustManagers, sr);
        };
    } catch(e) {}

    // ===== TrustManagerImpl (Android > 7) =====
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

        TrustManagerImpl.verifyChain.implementation = function() {
            console.log("[+] TrustManagerImpl.verifyChain bypassed");
            return arguments[0];
        };

        TrustManagerImpl.checkTrustedRecursive.implementation = function() {
            console.log("[+] TrustManagerImpl.checkTrustedRecursive bypassed");
            return Java.use("java.util.ArrayList").$new();
        };
    } catch(e) {}

    // ===== OkHTTP v3 (Quadruple Bypass) =====
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");

        // Method 1
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCerts) {
            console.log("[+] OkHTTP3 CertificatePinner.check bypassed for: " + hostname);
        };

        // Method 2
        try {
            CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(hostname, peerCerts) {
                console.log("[+] OkHTTP3 CertificatePinner.check (array) bypassed for: " + hostname);
            };
        } catch(e) {}

        // Method 3
        try {
            CertificatePinner.check$okhttp.implementation = function(hostname, sha256) {
                console.log("[+] OkHTTP3 CertificatePinner.check$okhttp bypassed for: " + hostname);
            };
        } catch(e) {}

        // Method 4 - Builder
        try {
            var Builder = Java.use("okhttp3.CertificatePinner$Builder");
            Builder.add.implementation = function(hostname, pins) {
                console.log("[+] OkHTTP3 CertificatePinner.Builder.add bypassed for: " + hostname);
                return this;
            };
        } catch(e) {}

        console.log("[+] OkHTTP3 bypass active");
    } catch(e) {}

    // ===== Trustkit (Triple Bypass) =====
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.TrustKit");
        TrustKit.initializeWithNetworkSecurityConfiguration.overload("android.content.Context").implementation = function(ctx) {
            console.log("[+] Trustkit initialization bypassed");
        };
        TrustKit.initializeWithNetworkSecurityConfiguration.overload("android.content.Context", "int").implementation = function(ctx, id) {
            console.log("[+] Trustkit initialization bypassed");
        };
    } catch(e) {}

    try {
        var PinningTrustManager = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        PinningTrustManager.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function(host, session) {
            console.log("[+] Trustkit OkHostnameVerifier bypassed for: " + host);
            return true;
        };
    } catch(e) {}

    try {
        var SystemTrustManager = Java.use("com.datatheorem.android.trustkit.pinning.SystemTrustManager");
        SystemTrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log("[+] Trustkit SystemTrustManager bypassed");
        };
    } catch(e) {}

    // ===== Appcelerator Titanium =====
    try {
        var PinningTrustManager = Java.use("appcelerator.https.PinningTrustManager");
        PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log("[+] Appcelerator PinningTrustManager bypassed");
        };
    } catch(e) {}

    // ===== Fabric / Twitter =====
    try {
        var PinningInfoProvider = Java.use("io.fabric.sdk.android.services.network.PinningInfoProvider");
        PinningInfoProvider.getPins.implementation = function() {
            console.log("[+] Fabric getPins bypassed");
            return Java.use("java.util.ArrayList").$new();
        };
    } catch(e) {}

    // ===== IBM MobileFirst / WorkLight =====
    try {
        var WLClient = Java.use("com.worklight.wlclient.api.WLClient");
        WLClient.pinTrustedCertificatePublicKey.overload("java.lang.String").implementation = function(cert) {
            console.log("[+] IBM WorkLight pinning bypassed");
        };
    } catch(e) {}

    try {
        var GatewayChallengeHandler = Java.use("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning");
        GatewayChallengeHandler.verify.overload("java.lang.String", "javax.net.ssl.SSLSocket").implementation = function(host, socket) {
            console.log("[+] IBM MobileFirst pinning bypassed for: " + host);
        };
    } catch(e) {}

    // ===== Conscrypt CertPinManager =====
    try {
        var CertPinManager = Java.use("com.android.org.conscrypt.CertPinManager");
        CertPinManager.isChainValid.overload("java.lang.String", "java.util.List").implementation = function(host, chain) {
            console.log("[+] Conscrypt CertPinManager bypassed for: " + host);
            return true;
        };
    } catch(e) {}

    // ===== CWAC-Netsecurity =====
    try {
        var CertPinManager = Java.use("com.commonsware.cwac.netsecurity.CertPinManager");
        CertPinManager.isChainValid.overload("java.lang.String", "java.util.List").implementation = function(host, chain) {
            console.log("[+] CWAC-Netsecurity bypassed for: " + host);
            return true;
        };
    } catch(e) {}

    // ===== Netty FingerprintTrustManagerFactory =====
    try {
        var FingerprintTrust = Java.use("io.netty.handler.ssl.util.FingerprintTrustManagerFactory");
        FingerprintTrust.checkTrusted.implementation = function(type, chain) {
            console.log("[+] Netty FingerprintTrustManagerFactory bypassed");
        };
    } catch(e) {}

    // ===== Squareup OkHTTP =====
    try {
        var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(host, peerCerts) {
            console.log("[+] Squareup OkHTTP CertificatePinner bypassed for: " + host);
        };
    } catch(e) {}

    // ===== Apache Cordova =====
    try {
        var WebViewClient = Java.use("org.apache.cordova.CordovaWebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] Apache Cordova SSL error bypassed");
            handler.proceed();
        };
    } catch(e) {}

    try {
        var WebViewEngine = Java.use("org.apache.cordova.engine.SystemWebViewClient");
        WebViewEngine.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] Apache Cordova engine SSL error bypassed");
            handler.proceed();
        };
    } catch(e) {}

    // ===== PhoneGap =====
    try {
        var GapViewClient = Java.use("com.phonegap.DroidGap$GapViewClient");
        GapViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] PhoneGap SSL error bypassed");
            handler.proceed();
        };
    } catch(e) {}

    // ===== Boye AbstractVerifier =====
    try {
        var AbstractVerifier = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
        AbstractVerifier.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean").implementation = function(host, cns, alts, strict) {
            console.log("[+] Boye AbstractVerifier bypassed for: " + host);
        };
    } catch(e) {}

    // ===== Appmattus CertificateTransparency =====
    try {
        var CTInterceptor = Java.use("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor");
        CTInterceptor.intercept.implementation = function(chain) {
            console.log("[+] Appmattus CertificateTransparency bypassed");
            return chain.proceed(chain.request());
        };
    } catch(e) {}

    // ===== Chromium Cronet =====
    try {
        var CronetEngine = Java.use("org.chromium.net.CronetEngine$Builder");
        CronetEngine.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function(bypass) {
            console.log("[+] Chromium Cronet pinning bypass enabled");
            return this.enablePublicKeyPinningBypassForLocalTrustAnchors(true);
        };
    } catch(e) {}

    try {
        var CronetUrlRequest = Java.use("org.chromium.net.impl.CronetUrlRequest");
        CronetUrlRequest.start.implementation = function() {
            console.log("[+] Chromium Cronet request started (monitoring)");
            return this.start();
        };
    } catch(e) {}

    // ===== Android WebView =====
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] WebView SSL error bypassed");
            handler.proceed();
        };
    } catch(e) {}

    // ===== HttpsURLConnection =====
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[+] HttpsURLConnection.setDefaultHostnameVerifier bypassed");
        };

        HttpsURLConnection.setSSLSocketFactory.implementation = function(sslSocketFactory) {
            console.log("[+] HttpsURLConnection.setSSLSocketFactory bypassed");
        };

        HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[+] HttpsURLConnection.setHostnameVerifier bypassed");
        };
    } catch(e) {}

    // ===== HostnameVerifier Universal Bypass =====
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var AllowAllHostnameVerifier = Java.registerClass({
            name: "com.mega.bypass.AllowAllHostnameVerifier",
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    console.log("[+] HostnameVerifier bypassed for: " + hostname);
                    return true;
                }
            }
        });
    } catch(e) {}

    console.log("[*] MEGA SSL Pinning Bypass Active");
    console.log("[*] Monitoring 30+ SSL pinning implementations...");
});
'''

# ============================================
# FLUTTER SSL PINNING BYPASS
# ============================================

ANDROID_FLUTTER_SSL_BYPASS = '''
/**
 * Flutter SSL Pinning Bypass
 * Bypasses certificate pinning in Flutter applications
 * Uses libflutter.so pattern matching
 */

console.log("[*] Starting Flutter SSL Pinning Bypass...");

// Method 1: Pattern-based bypass (most reliable)
setTimeout(function() {
    try {
        // Pattern for ssl_crypto_x509_session_verify_cert_chain
        var patterns = [
            // Pattern 1: Common Flutter pinning pattern
            "ff 03 05 d1 fd 7b 0f a9 bc de 05 94 08 0a 80 52 48",
            // Pattern 2: Alternative pattern
            "2d e9 f0 4f a3 b0 81 46 50 20 10 70",
            // Pattern 3: Another variant
            "f8 b5 04 46 0d 46 16 46"
        ];

        var moduleName = "libflutter.so";
        var modules = Process.enumerateModules();

        for (var m = 0; m < modules.length; m++) {
            var module = modules[m];
            if (module.name === moduleName) {
                console.log("[+] Found " + moduleName + " at " + module.base);

                for (var p = 0; p < patterns.length; p++) {
                    try {
                        var matches = Memory.scanSync(module.base, module.size, patterns[p]);
                        if (matches.length > 0) {
                            console.log("[+] Pattern " + (p+1) + " found at " + matches.length + " location(s)");

                            for (var i = 0; i < matches.length; i++) {
                                Interceptor.attach(matches[i].address, {
                                    onLeave: function(retval) {
                                        console.log("[+] Flutter SSL check bypassed (pattern)");
                                        retval.replace(0x1); // Return true
                                    }
                                });
                            }
                        }
                    } catch(e) {}
                }
                break;
            }
        }
    } catch(e) {
        console.log("[-] Pattern-based bypass failed: " + e);
    }
}, 1000);

// Method 2: Symbol-based bypass
setTimeout(function() {
    try {
        var ssl_verify = Module.findExportByName("libflutter.so", "ssl_crypto_x509_session_verify_cert_chain");
        if (ssl_verify) {
            Interceptor.attach(ssl_verify, {
                onLeave: function(retval) {
                    console.log("[+] Flutter ssl_crypto_x509_session_verify_cert_chain bypassed");
                    retval.replace(0x1);
                }
            });
            console.log("[+] Symbol-based Flutter bypass active");
        }
    } catch(e) {}
}, 1500);

// Method 3: Java-level Flutter bypass
Java.perform(function() {
    try {
        var HttpCertificatePinning = Java.use("diefferson.http_certificate_pinning.HttpCertificatePinning");
        HttpCertificatePinning.checkConnexion.implementation = function() {
            console.log("[+] Flutter HttpCertificatePinning bypassed");
            return true;
        };
    } catch(e) {}

    // ssl_pinning_plugin
    try {
        var SslPinning = Java.use("com.macif.plugin.sslpinningplugin.SslPinningPlugin");
        SslPinning.checkConnexion.implementation = function() {
            console.log("[+] Flutter SslPinningPlugin bypassed");
            return true;
        };
    } catch(e) {}
});

console.log("[*] Flutter SSL Pinning Bypass Active");
'''

# ============================================
# HTTP TRAFFIC INTERCEPTION
# ============================================

ANDROID_TRAFFIC_INTERCEPTION = '''
/**
 * HTTP Traffic Interception
 * Captures and logs HTTP/HTTPS request and response data
 * Useful for analyzing app communication
 */

Java.perform(function() {
    console.log("[*] Starting HTTP Traffic Interception...");

    // ===== OkHttp3 Interceptor =====
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Interceptor = Java.use("okhttp3.Interceptor");
        var Buffer = Java.use("okio.Buffer");

        // Create logging interceptor
        var LoggingInterceptor = Java.registerClass({
            name: "com.traffic.LoggingInterceptor",
            implements: [Interceptor],
            methods: {
                intercept: function(chain) {
                    var request = chain.request();
                    var url = request.url().toString();
                    var method = request.method();

                    console.log("\\n=== HTTP Request ===");
                    console.log("[>] " + method + " " + url);

                    // Log headers
                    var headers = request.headers();
                    for (var i = 0; i < headers.size(); i++) {
                        console.log("[H] " + headers.name(i) + ": " + headers.value(i));
                    }

                    // Log body for POST/PUT
                    var body = request.body();
                    if (body !== null && (method === "POST" || method === "PUT")) {
                        try {
                            var buffer = Buffer.$new();
                            body.writeTo(buffer);
                            var bodyStr = buffer.readUtf8();
                            if (bodyStr.length < 2000) {
                                console.log("[B] " + bodyStr);
                            } else {
                                console.log("[B] (body too large: " + bodyStr.length + " bytes)");
                            }
                        } catch(e) {}
                    }

                    // Process response
                    var response = chain.proceed(request);

                    console.log("\\n=== HTTP Response ===");
                    console.log("[<] " + response.code() + " " + url);

                    // Log response body (clone to read multiple times)
                    try {
                        var responseBody = response.body();
                        if (responseBody !== null) {
                            var source = responseBody.source();
                            source.request(Long.MAX_VALUE);
                            var respBuffer = source.buffer().clone();
                            var respStr = respBuffer.readUtf8();
                            if (respStr.length < 2000) {
                                console.log("[R] " + respStr);
                            } else {
                                console.log("[R] (response too large: " + respStr.length + " bytes)");
                            }
                        }
                    } catch(e) {}

                    return response;
                }
            }
        });

        console.log("[+] OkHttp3 traffic interceptor ready");
    } catch(e) {
        console.log("[-] OkHttp3 interceptor setup failed");
    }

    // ===== HttpURLConnection Interceptor =====
    try {
        var URL = Java.use("java.net.URL");
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");

        URL.openConnection.overload().implementation = function() {
            var conn = this.openConnection();
            var url = this.toString();
            console.log("\\n[HTTP] Connection opened: " + url);
            return conn;
        };
    } catch(e) {}

    // ===== WebView Request Interceptor =====
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");

        WebViewClient.shouldInterceptRequest.overload("android.webkit.WebView", "android.webkit.WebResourceRequest").implementation = function(view, request) {
            var url = request.getUrl().toString();
            var method = request.getMethod();
            console.log("\\n[WebView] " + method + " " + url);
            return this.shouldInterceptRequest(view, request);
        };
    } catch(e) {}

    console.log("[*] HTTP Traffic Interception Active");
    console.log("[*] Monitoring OkHttp3, HttpURLConnection, WebView...");
});
'''

# ============================================
# ANDROID ANTI-DEBUG BYPASS
# ============================================

ANDROID_ANTI_DEBUG = '''
/**
 * Anti-Debug/Anti-Frida Bypass
 * Bypasses debugger and Frida detection
 */

Java.perform(function() {
    console.log("[*] Starting Anti-Debug Bypass...");

    // ===== Debug.isDebuggerConnected Bypass =====
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[+] Bypassed Debug.isDebuggerConnected()");
        return false;
    };

    // ===== TracerPid Check Bypass =====
    var BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.overload().implementation = function() {
        var line = this.readLine();
        if (line != null && line.indexOf("TracerPid") !== -1) {
            console.log("[+] Hiding TracerPid");
            return "TracerPid:\\t0";
        }
        return line;
    };

    // ===== Hide Frida Server Port =====
    var Socket = Java.use("java.net.Socket");
    Socket.$init.overload("java.lang.String", "int").implementation = function(host, port) {
        if (port === 27042 || port === 27043) {
            console.log("[+] Blocking Frida detection socket: " + port);
            throw Java.use("java.net.ConnectException").$new("Connection refused");
        }
        return this.$init(host, port);
    };

    // ===== Hide Frida Libraries =====
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.loadLibrary.overload("java.lang.String").implementation = function(library) {
        if (library.indexOf("frida") !== -1) {
            console.log("[+] Blocking frida library load");
            return;
        }
        return this.loadLibrary(library);
    };

    console.log("[*] Anti-Debug Bypass Active");
});
'''

# ============================================
# iOS JAILBREAK DETECTION BYPASS
# ============================================

IOS_JAILBREAK_BYPASS = '''
/**
 * iOS Jailbreak Detection Bypass
 * Universal bypass for common jailbreak checks
 */

if (ObjC.available) {
    console.log("[*] Starting iOS Jailbreak Detection Bypass...");

    // ===== File Existence Checks =====
    var fileManager = ObjC.classes.NSFileManager.defaultManager();

    Interceptor.attach(ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation, {
        onEnter: function(args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            var jailbreakPaths = [
                "/Applications/Cydia.app",
                "/Library/MobileSubstrate/MobileSubstrate.dylib",
                "/bin/bash",
                "/usr/sbin/sshd",
                "/etc/apt",
                "/private/var/lib/apt/",
                "/usr/bin/ssh",
                "/var/cache/apt",
                "/var/lib/cydia",
                "/var/tmp/cydia.log",
                "/private/var/stash",
                "/Applications/blackra1n.app",
                "/Applications/FakeCarrier.app",
                "/Applications/Icy.app",
                "/Applications/IntelliScreen.app",
                "/Applications/SBSettings.app",
                "/private/var/mobile/Library/SBSettings/Themes"
            ];

            for (var i = 0; i < jailbreakPaths.length; i++) {
                if (this.path.indexOf(jailbreakPaths[i]) !== -1) {
                    console.log("[+] Hiding jailbreak file: " + this.path);
                    retval.replace(0);
                    return;
                }
            }
        }
    });

    // ===== URL Scheme Checks =====
    Interceptor.attach(ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
        onEnter: function(args) {
            this.url = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            var jbURLs = ["cydia://", "sileo://", "zbra://"];
            for (var i = 0; i < jbURLs.length; i++) {
                if (this.url.indexOf(jbURLs[i]) !== -1) {
                    console.log("[+] Hiding jailbreak URL scheme: " + this.url);
                    retval.replace(0);
                    return;
                }
            }
        }
    });

    // ===== Sandbox Escape Checks =====
    Interceptor.attach(Module.findExportByName(null, "fork"), {
        onLeave: function(retval) {
            console.log("[+] Bypassed fork() check");
            retval.replace(-1);
        }
    });

    // ===== dyld Image Check =====
    Interceptor.attach(Module.findExportByName(null, "_dyld_image_count"), {
        onLeave: function(retval) {
            // Don't modify, just log
            console.log("[*] dyld_image_count called");
        }
    });

    console.log("[*] iOS Jailbreak Detection Bypass Active");

} else {
    console.log("[-] Objective-C runtime not available");
}
'''

IOS_SSL_PINNING_BYPASS = '''
/**
 * iOS SSL Pinning Bypass
 * Works with AFNetworking, Alamofire, NSURLSession
 */

if (ObjC.available) {
    console.log("[*] Starting iOS SSL Pinning Bypass...");

    // ===== NSURLSession Bypass =====
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

    Interceptor.attach(ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
        onEnter: function(args) {
            console.log("[+] NSURLSession dataTask intercepted");
        }
    });

    // ===== AFNetworking Bypass =====
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            Interceptor.attach(AFSecurityPolicy["- setSSLPinningMode:"].implementation, {
                onEnter: function(args) {
                    console.log("[+] Bypassing AFSecurityPolicy SSL Pinning Mode");
                    args[2] = ptr(0); // AFSSLPinningModeNone
                }
            });

            Interceptor.attach(AFSecurityPolicy["- setAllowInvalidCertificates:"].implementation, {
                onEnter: function(args) {
                    console.log("[+] Allowing invalid certificates");
                    args[2] = ptr(1);
                }
            });
        }
    } catch (e) {
        console.log("[-] AFNetworking not found");
    }

    // ===== TrustKit Bypass =====
    try {
        var TrustKit = ObjC.classes.TrustKit;
        if (TrustKit) {
            Interceptor.attach(TrustKit["+ initSharedInstanceWithConfiguration:"].implementation, {
                onEnter: function(args) {
                    console.log("[+] Bypassing TrustKit initialization");
                }
            });
        }
    } catch (e) {
        console.log("[-] TrustKit not found");
    }

    // ===== SecTrustEvaluate Bypass =====
    var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
    if (SecTrustEvaluate) {
        Interceptor.attach(SecTrustEvaluate, {
            onLeave: function(retval) {
                console.log("[+] Bypassed SecTrustEvaluate");
                retval.replace(0); // errSecSuccess
            }
        });
    }

    // ===== SecTrustEvaluateWithError (iOS 12+) =====
    var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
        Interceptor.attach(SecTrustEvaluateWithError, {
            onLeave: function(retval) {
                console.log("[+] Bypassed SecTrustEvaluateWithError");
                retval.replace(1); // true
            }
        });
    }

    console.log("[*] iOS SSL Pinning Bypass Active");

} else {
    console.log("[-] Objective-C runtime not available");
}
'''

# ============================================
# COMBINED MASTER SCRIPTS
# ============================================

ANDROID_MASTER_BYPASS = '''
/**
 * Android Master Bypass Script
 * Combines all Android bypasses into one comprehensive script
 *
 * Generated by Mobile Security Analyzer
 */

// Configuration
var config = {
    rootDetection: true,
    sslPinning: true,
    antiDebug: true,
    verbose: true
};

function log(msg) {
    if (config.verbose) {
        console.log(msg);
    }
}

Java.perform(function() {
    log("[*] Mobile Security Analyzer - Master Bypass Script");
    log("[*] Starting comprehensive bypass...");

    // ===== ROOT DETECTION BYPASS =====
    if (config.rootDetection) {
        log("[*] Enabling Root Detection Bypass...");

        // File checks
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var rootIndicators = [
                "su", "superuser", "magisk", "busybox",
                "xposed", "substrate", "frida"
            ];
            for (var i = 0; i < rootIndicators.length; i++) {
                if (path.toLowerCase().indexOf(rootIndicators[i]) !== -1) {
                    log("[+] Root bypass: " + path);
                    return false;
                }
            }
            return this.exists.call(this);
        };

        // Build properties
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        Build.FINGERPRINT.value = Build.FINGERPRINT.value.replace("test-keys", "release-keys");

        // RootBeer
        try {
            var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
            RootBeer.isRooted.implementation = function() { return false; };
            RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
            log("[+] RootBeer bypassed");
        } catch(e) {}

        log("[*] Root Detection Bypass Active");
    }

    // ===== SSL PINNING BYPASS =====
    if (config.sslPinning) {
        log("[*] Enabling SSL Pinning Bypass...");

        // Custom TrustManager
        var TrustManager = Java.registerClass({
            name: "com.bypass.TrustManager",
            implements: [Java.use("javax.net.ssl.X509TrustManager")],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        // SSLContext
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function(km, tm, sr) {
            log("[+] SSLContext.init bypassed");
            this.init(km, [TrustManager.$new()], sr);
        };

        // OkHttp3
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(h, c) {
                log("[+] OkHttp3 pinning bypassed: " + h);
            };
        } catch(e) {}

        // TrustManagerImpl (Android 7+)
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            TrustManagerImpl.verifyChain.implementation = function() {
                log("[+] TrustManagerImpl bypassed");
                return Java.use("java.util.ArrayList").$new();
            };
        } catch(e) {}

        log("[*] SSL Pinning Bypass Active");
    }

    // ===== ANTI-DEBUG BYPASS =====
    if (config.antiDebug) {
        log("[*] Enabling Anti-Debug Bypass...");

        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            return false;
        };

        log("[*] Anti-Debug Bypass Active");
    }

    log("[*] All bypasses initialized successfully!");
    log("[*] Monitoring for security checks...");
});
'''

IOS_MASTER_BYPASS = '''
/**
 * iOS Master Bypass Script
 * Combines all iOS bypasses into one comprehensive script
 *
 * Generated by Mobile Security Analyzer
 */

// Configuration
var config = {
    jailbreakDetection: true,
    sslPinning: true,
    verbose: true
};

function log(msg) {
    if (config.verbose) {
        console.log(msg);
    }
}

if (ObjC.available) {
    log("[*] Mobile Security Analyzer - iOS Master Bypass Script");
    log("[*] Starting comprehensive bypass...");

    // ===== JAILBREAK DETECTION BYPASS =====
    if (config.jailbreakDetection) {
        log("[*] Enabling Jailbreak Detection Bypass...");

        var jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt"
        ];

        // File existence
        Interceptor.attach(ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation, {
            onEnter: function(args) { this.path = ObjC.Object(args[2]).toString(); },
            onLeave: function(retval) {
                for (var i = 0; i < jailbreakPaths.length; i++) {
                    if (this.path.indexOf(jailbreakPaths[i]) !== -1) {
                        log("[+] Hiding: " + this.path);
                        retval.replace(0);
                        return;
                    }
                }
            }
        });

        // URL schemes
        Interceptor.attach(ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
            onEnter: function(args) { this.url = ObjC.Object(args[2]).toString(); },
            onLeave: function(retval) {
                if (this.url.indexOf("cydia://") !== -1 || this.url.indexOf("sileo://") !== -1) {
                    log("[+] Hiding URL: " + this.url);
                    retval.replace(0);
                }
            }
        });

        log("[*] Jailbreak Detection Bypass Active");
    }

    // ===== SSL PINNING BYPASS =====
    if (config.sslPinning) {
        log("[*] Enabling SSL Pinning Bypass...");

        // SecTrustEvaluate
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onLeave: function(retval) {
                    log("[+] SecTrustEvaluate bypassed");
                    retval.replace(0);
                }
            });
        }

        // SecTrustEvaluateWithError (iOS 12+)
        var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onLeave: function(retval) {
                    log("[+] SecTrustEvaluateWithError bypassed");
                    retval.replace(1);
                }
            });
        }

        // AFNetworking
        try {
            var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
            if (AFSecurityPolicy) {
                Interceptor.attach(AFSecurityPolicy["- setSSLPinningMode:"].implementation, {
                    onEnter: function(args) {
                        log("[+] AFNetworking SSL mode bypassed");
                        args[2] = ptr(0);
                    }
                });
            }
        } catch(e) {}

        log("[*] SSL Pinning Bypass Active");
    }

    log("[*] All bypasses initialized successfully!");

} else {
    console.log("[-] Objective-C runtime not available");
}
'''


# Template Registry
FRIDA_TEMPLATES: Dict[str, FridaTemplate] = {
    "android_root_generic": FridaTemplate(
        id="android_root_generic",
        name="Advanced Root Detection Bypass",
        category=BypassCategory.ROOT_DETECTION,
        platform="android",
        description="Comprehensive root bypass including KernelSU, Magisk, 40+ paths, ProcessBuilder, and Package Manager",
        targets=["java.io.File", "java.lang.Runtime", "android.os.Build", "java.lang.ProcessBuilder", "java.io.UnixFileSystem"],
        script=ANDROID_ROOT_GENERIC,
        difficulty="easy"
    ),
    "android_rootbeer": FridaTemplate(
        id="android_rootbeer",
        name="RootBeer Library Bypass",
        category=BypassCategory.ROOT_DETECTION,
        platform="android",
        description="Complete bypass for the RootBeer root detection library",
        targets=["com.scottyab.rootbeer.RootBeer"],
        script=ANDROID_ROOTBEER_BYPASS,
        difficulty="easy"
    ),
    "android_magisk": FridaTemplate(
        id="android_magisk",
        name="Magisk Detection Bypass",
        category=BypassCategory.ROOT_DETECTION,
        platform="android",
        description="Hides Magisk presence from apps including package manager and mount points",
        targets=["android.app.ApplicationPackageManager", "java.io.BufferedReader"],
        script=ANDROID_MAGISK_BYPASS,
        difficulty="medium"
    ),
    "android_emulator": FridaTemplate(
        id="android_emulator",
        name="Emulator Detection Bypass",
        category=BypassCategory.EMULATOR_DETECTION,
        platform="android",
        description="Spoofs Build properties, TelephonyManager, and hides emulator-specific files to bypass emulator detection",
        targets=["android.os.Build", "android.os.SystemProperties", "android.telephony.TelephonyManager"],
        script=ANDROID_EMULATOR_BYPASS,
        difficulty="medium"
    ),
    "android_native": FridaTemplate(
        id="android_native",
        name="Native Level Bypass (libc.so)",
        category=BypassCategory.ROOT_DETECTION,
        platform="android",
        description="Low-level native hooks for fopen, access, system, stat, and strstr to bypass root detection at C level",
        targets=["libc.so:fopen", "libc.so:access", "libc.so:system", "libc.so:stat", "libc.so:strstr"],
        script=ANDROID_NATIVE_BYPASS,
        difficulty="hard"
    ),
    "android_ssl_universal": FridaTemplate(
        id="android_ssl_universal",
        name="Universal SSL Pinning Bypass",
        category=BypassCategory.SSL_PINNING,
        platform="android",
        description="Comprehensive SSL pinning bypass for TrustManager, OkHttp, HttpsURLConnection, and WebView",
        targets=["javax.net.ssl.SSLContext", "okhttp3.CertificatePinner", "javax.net.ssl.HttpsURLConnection"],
        script=ANDROID_SSL_UNIVERSAL,
        difficulty="easy"
    ),
    "android_network_security": FridaTemplate(
        id="android_network_security",
        name="Network Security Config Bypass",
        category=BypassCategory.SSL_PINNING,
        platform="android",
        description="Bypasses Android's Network Security Configuration for cleartext and pinning",
        targets=["android.security.net.config.NetworkSecurityConfig"],
        script=ANDROID_NETWORK_SECURITY_CONFIG,
        difficulty="easy"
    ),
    "android_ssl_mega": FridaTemplate(
        id="android_ssl_mega",
        name="MEGA SSL Pinning Bypass (30+ Libraries)",
        category=BypassCategory.SSL_PINNING,
        platform="android",
        description="Comprehensive bypass covering 30+ SSL implementations including Trustkit, Fabric, IBM MobileFirst, Conscrypt, Netty, Cronet, with dynamic SSLPeerUnverifiedException auto-patcher",
        targets=["TrustManager", "OkHTTP3", "Trustkit", "Fabric", "IBM WorkLight", "Conscrypt", "CWAC-Netsecurity", "Netty", "Cronet", "Cordova", "PhoneGap"],
        script=ANDROID_SSL_MEGA_BYPASS,
        difficulty="easy"
    ),
    "android_flutter_ssl": FridaTemplate(
        id="android_flutter_ssl",
        name="Flutter SSL Pinning Bypass",
        category=BypassCategory.FLUTTER_BYPASS,
        platform="android",
        description="Bypasses SSL pinning in Flutter apps using libflutter.so pattern matching and Java-level hooks",
        targets=["libflutter.so", "HttpCertificatePinning", "SslPinningPlugin"],
        script=ANDROID_FLUTTER_SSL_BYPASS,
        difficulty="medium"
    ),
    "android_traffic_intercept": FridaTemplate(
        id="android_traffic_intercept",
        name="HTTP Traffic Interception",
        category=BypassCategory.TRAFFIC_INTERCEPTION,
        platform="android",
        description="Captures and logs HTTP/HTTPS requests and responses from OkHttp3, HttpURLConnection, and WebView",
        targets=["okhttp3.OkHttpClient", "java.net.URL", "android.webkit.WebViewClient"],
        script=ANDROID_TRAFFIC_INTERCEPTION,
        difficulty="medium"
    ),
    "android_anti_debug": FridaTemplate(
        id="android_anti_debug",
        name="Anti-Debug/Anti-Frida Bypass",
        category=BypassCategory.ANTI_DEBUG,
        platform="android",
        description="Bypasses debugger detection and Frida detection mechanisms",
        targets=["android.os.Debug", "java.net.Socket"],
        script=ANDROID_ANTI_DEBUG,
        difficulty="medium"
    ),
    "android_master": FridaTemplate(
        id="android_master",
        name="Android Master Bypass",
        category=BypassCategory.ROOT_DETECTION,
        platform="android",
        description="Comprehensive bypass combining root detection, SSL pinning, and anti-debug",
        targets=["Multiple"],
        script=ANDROID_MASTER_BYPASS,
        difficulty="easy"
    ),
    "ios_jailbreak": FridaTemplate(
        id="ios_jailbreak",
        name="iOS Jailbreak Detection Bypass",
        category=BypassCategory.JAILBREAK_DETECTION,
        platform="ios",
        description="Universal bypass for iOS jailbreak detection including file checks and URL schemes",
        targets=["NSFileManager", "UIApplication"],
        script=IOS_JAILBREAK_BYPASS,
        difficulty="easy"
    ),
    "ios_ssl": FridaTemplate(
        id="ios_ssl",
        name="iOS SSL Pinning Bypass",
        category=BypassCategory.SSL_PINNING,
        platform="ios",
        description="Bypasses SSL pinning for AFNetworking, TrustKit, and SecTrust APIs",
        targets=["AFSecurityPolicy", "TrustKit", "SecTrustEvaluate"],
        script=IOS_SSL_PINNING_BYPASS,
        difficulty="easy"
    ),
    "ios_master": FridaTemplate(
        id="ios_master",
        name="iOS Master Bypass",
        category=BypassCategory.JAILBREAK_DETECTION,
        platform="ios",
        description="Comprehensive iOS bypass combining jailbreak detection and SSL pinning",
        targets=["Multiple"],
        script=IOS_MASTER_BYPASS,
        difficulty="easy"
    ),
}


def get_template(template_id: str) -> Optional[FridaTemplate]:
    """Get a specific template by ID"""
    return FRIDA_TEMPLATES.get(template_id)


def get_templates_by_category(category: BypassCategory) -> List[FridaTemplate]:
    """Get all templates for a specific category"""
    return [t for t in FRIDA_TEMPLATES.values() if t.category == category]


def get_templates_by_platform(platform: str) -> List[FridaTemplate]:
    """Get all templates for a specific platform"""
    return [t for t in FRIDA_TEMPLATES.values() if t.platform == platform or t.platform == "both"]


def get_all_templates() -> List[FridaTemplate]:
    """Get all available templates"""
    return list(FRIDA_TEMPLATES.values())


def combine_scripts(template_ids: List[str]) -> str:
    """Combine multiple templates into one script"""
    scripts = []
    for tid in template_ids:
        template = get_template(tid)
        if template:
            scripts.append(f"// ===== {template.name} =====")
            scripts.append(template.script)
            scripts.append("")

    return "\n".join(scripts)


def generate_custom_script(
    findings: Dict,
    platform: str = "android",
    include_traffic_intercept: bool = False,
    include_native_bypass: bool = False
) -> str:
    """
    Generate a custom Frida script based on detected security mechanisms
    Returns a combined script targeting the specific detections

    Args:
        findings: Dictionary of detected security mechanisms
        platform: "android" or "ios"
        include_traffic_intercept: Include HTTP traffic interception
        include_native_bypass: Include native-level (libc.so) bypasses
    """
    template_ids = []

    if platform == "android":
        # Always include advanced root bypass as base
        template_ids.append("android_root_generic")

        # Check for specific detection mechanisms
        root_findings = findings.get("root_detection", [])
        ssl_findings = findings.get("ssl_pinning", [])
        emulator_findings = findings.get("emulator_detection", [])
        flutter_findings = findings.get("flutter", [])

        # Root detection libraries
        for finding in root_findings:
            pattern = finding.get("pattern_matched", "").lower()
            if "rootbeer" in pattern:
                template_ids.append("android_rootbeer")
            if "magisk" in pattern:
                template_ids.append("android_magisk")
            if "kernelsu" in pattern or "ksu" in pattern:
                # Already covered by advanced root generic
                pass

        # Emulator detection
        if emulator_findings or any("emulator" in f.get("pattern_matched", "").lower() for f in root_findings):
            template_ids.append("android_emulator")

        # SSL pinning libraries
        ssl_libs_found = set()
        for finding in ssl_findings:
            pattern = finding.get("pattern_matched", "").lower()
            if "okhttp" in pattern:
                ssl_libs_found.add("okhttp")
            if "trustkit" in pattern:
                ssl_libs_found.add("trustkit")
            if "conscrypt" in pattern:
                ssl_libs_found.add("conscrypt")
            if "fabric" in pattern:
                ssl_libs_found.add("fabric")
            if "cronet" in pattern or "chromium" in pattern:
                ssl_libs_found.add("cronet")
            if "cordova" in pattern or "phonegap" in pattern:
                ssl_libs_found.add("cordova")
            if "worklight" in pattern or "mobilefirst" in pattern:
                ssl_libs_found.add("ibm")

        # If multiple SSL libraries detected, use MEGA bypass
        if len(ssl_libs_found) >= 2 or ssl_findings:
            template_ids.append("android_ssl_mega")
        else:
            template_ids.append("android_ssl_universal")

        # Flutter detection
        if flutter_findings or any("flutter" in f.get("pattern_matched", "").lower() for f in ssl_findings):
            template_ids.append("android_flutter_ssl")

        # Optional: Native-level bypass for hardened apps
        if include_native_bypass:
            template_ids.append("android_native")

        # Optional: Traffic interception
        if include_traffic_intercept:
            template_ids.append("android_traffic_intercept")

        # Always include anti-debug
        template_ids.append("android_anti_debug")

    elif platform == "ios":
        template_ids.append("ios_master")
        template_ids.append("ios_ssl")

    # Remove duplicates while preserving order
    seen = set()
    unique_ids = []
    for tid in template_ids:
        if tid not in seen:
            seen.add(tid)
            unique_ids.append(tid)

    return combine_scripts(unique_ids)


def generate_ultimate_bypass(platform: str = "android") -> str:
    """
    Generate the ultimate bypass script with ALL techniques combined
    Use this for maximum compatibility against heavily protected apps
    """
    if platform == "android":
        template_ids = [
            "android_root_generic",
            "android_rootbeer",
            "android_magisk",
            "android_emulator",
            "android_native",
            "android_ssl_mega",
            "android_flutter_ssl",
            "android_anti_debug",
        ]
    else:
        template_ids = [
            "ios_jailbreak",
            "ios_ssl",
        ]

    return combine_scripts(template_ids)
