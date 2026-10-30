plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.zerobreach.scanner"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.zerobreach.scanner"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    // New app, new pinned key (2026-10-30). Keystore lives in the persistent
    // workspace (signing/zerobreach.keystore) so VM replacement cannot change
    // it and break update installs, the lesson from PinPoint.
    signingConfigs {
        getByName("debug") {
            storeFile = file("../signing/zerobreach.keystore")
            storePassword = "zerobreach"
            keyAlias = "zerobreach"
            keyPassword = "zerobreach"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // Deliberately no AndroidX / no third-party deps: framework Activity only.
    // Keeps the APK small, auditable, and fully offline to build.
}
