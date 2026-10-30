// The Android demo is a standalone Gradle project rooted at android/, while the C
// sources it compiles live one level up. Keeping it separate means a desktop build
// never needs Gradle and a Gradle build never needs the CLI.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "cairn-android"
include(":app")