// The Android demo module.
//
// The C library is compiled by CMake through externalNativeBuild, so the same sources
// that build on Linux, Windows and macOS produce libcairn.so here. Only
// android/cairn_jni.c is Android specific.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "org.cairn.demo"
    compileSdk = 34
    ndkVersion = "26.1.10909125"

    defaultConfig {
        applicationId = "org.cairn.demo"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.2"

        ndk {
            // arm64 covers current phones, armeabi-v7a older ones, x86_64 emulators.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                // The shared object must contain the JNI entry points; tests and the CLI
                // make no sense inside an APK.
                arguments += listOf(
                    "-DCAIRN_ANDROID_SHARED=ON",
                    "-DCAIRN_BUILD_TESTS=OFF",
                    "-DCAIRN_BUILD_CLI=OFF"
                )
                cFlags += listOf("-O2")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("../../CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

dependencies {
    // Nothing. The demo extends the platform Activity and draws its own views, so the
    // only code in the APK is the library and this app.
}
