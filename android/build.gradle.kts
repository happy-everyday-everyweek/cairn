// Android demo build.
//
// The C library is compiled by CMake through externalNativeBuild, so the same
// sources that build on Linux, Windows and macOS produce libcairn.so here. Only
// android/cairn_jni.c is Android specific.
//
// The Kotlin sources live directly under android/ rather than in the usual
// src/main/java tree, because they sit next to the JNI bridge and the CMake file
// they belong with. sourceSets below points Gradle at them.
plugins {
    id("com.android.application") version "8.5.2"
    id("org.jetbrains.kotlin.android") version "1.9.24"
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
        versionName = "0.1"

        ndk {
            // The three ABIs that cover essentially every phone in use.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                // The shared library must contain the JNI entry points, and the
                // tests and CLI make no sense inside an APK.
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
            path = file("../CMakeLists.txt")
            version = "3.22.1"
        }
    }

    sourceSets {
        getByName("main") {
            manifest.srcFile("AndroidManifest.xml")
            java.setSrcDirs(listOf("."))
            res.setSrcDirs(listOf("res"))
            // Only Kotlin files belong in the java source set here.
            java.includes += listOf("*.kt")
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
    implementation("androidx.appcompat:appcompat:1.7.0")
}