// Plugin versions live here so the module file stays about the module. A build for
// the desktop targets never reads any of this.
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}