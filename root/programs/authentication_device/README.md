# How to use
Add the necessary information for push notifications.

- /lib/configs/app_fcm.dart
- /android/app/google-services.json

To change the authentication server to be used,  
change the URL and parameters in the following file.

- /lib/configs/app_auth.dart

For the settings of Private-Use URI Scheme Redirection and  
Claimed Https Scheme URI Redirection, please set them in the following files.

- /android/app/src/main/AndroidManifest.xml
- /android/app/build.gradle.kts

If the authentication server uses a self-signed certificate,  
add the certificate to the following location to allow for self-signed certificates.  
This file can be exported as a CER in DER from the location bar of the browser.

- /android/app/src/debug/res/raw/my_ca.cer

# Server URL
Pass the root URL of the running MultiPurposeAuthSite with `--dart-define-from-file`.  
The following files are for local sites started by `test.ps1` (the endpoints are at the root).

- mpas.core.json : net10.0 (https://localhost:44300)
- mpas.netfx.json : net48 (https://localhost:44302)

Without the file, `https://localhost:44300` is used.  
A real Android device cannot reach `localhost`. Pass a file with a URL the device can reach.

# Web (PWA)
Web Push requires the Firebase web app configuration and a VAPID key.  
Copy `firebase_web.sample.json` to `firebase_web.json` and fill in the values  
from the Firebase console. `firebase_web.json` is ignored by git.

- Project settings > General > Your apps > (Web app) : `FIREBASE_*`
- Project settings > Cloud Messaging > Web Push certificates : `FIREBASE_VAPID_KEY`

Sign-in on the web uses the client `AuthenticationDevice_Web` (a public client with PKCE).  
Its `redirect_uri` is `http://localhost:5610/`, so run the app on that port.

    flutter run -d chrome --web-port 5610 --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json
    flutter build web --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json

Without `firebase_web.json`, the app starts without push notifications.
