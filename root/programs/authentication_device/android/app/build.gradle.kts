plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
    // FCM（firebase_messaging）の構成ファイル google-services.json を読み込む
    id("com.google.gms.google-services")
}

android {
    namespace = "com.opentouryo.authentication_device"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        // flutter_local_notifications が要求する（同パッケージ README の desugaring の節）
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        applicationId = "com.opentouryo.authentication_device"
        // flutter_local_notifications / flutter_appauth などが minSdk 24 以上を要求する。
        // Flutter 3.41 の既定（flutter.minSdkVersion）も 24。
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        // flutter_appauth のリダイレクト（lib/configs/app_auth.dart の redirectUrl と一致させる）
        manifestPlaceholders["appAuthRedirectScheme"] = "com.opentouryo"
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}

dependencies {
    // flutter_local_notifications が要求する（同パッケージ README の desugaring の節）
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
}
