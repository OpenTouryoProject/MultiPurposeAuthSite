Click [here](Readme.ja.md) for Japanese version of this file.

# How to use
Step-by-step procedures (settings files, starting the sites, trying CIBA) are in [CHEATSHEET.md](CHEATSHEET.md) (Japanese).

## Settings
Values that differ by environment are passed with `--dart-define-from-file`, not written in the source.

| What | Where |
|---|---|
| Server URL | `mpas.core.json` / `mpas.netfx.json` (`MPAS_BASE_URL`). See "Server URL" |
| Firebase for the web and the VAPID key | `firebase_web.json` (`FIREBASE_*`). See "Web (PWA)" |
| Firebase for Android | /android/app/google-services.json |

The client settings are written in /lib/configs/app_auth.dart.  
They must match the client registrations on the server (`OAuth2ClientsInformation`).

- Android / iOS : `clientId`, `redirectUrl`
- Web : `webClientId`, `webRedirectUrl` (can be overridden with `MPAS_WEB_REDIRECT_URI`)

The server-side settings (the client registrations and the key for sending notifications) are described in CHEATSHEET.md section 4.

## Android
For the settings of Private-Use URI Scheme Redirection and  
Claimed Https Scheme URI Redirection, please set them in the following files.

- /android/app/src/main/AndroidManifest.xml
- /android/app/build.gradle.kts

If the authentication server uses a self-signed certificate,  
add the certificate to the following location to allow for self-signed certificates (debug builds only).  
This file can be exported as a CER in DER from the location bar of the browser.

- /android/app/src/debug/res/raw/my_ca.cer

# Server URL
Pass the root URL where MultiPurposeAuthSite is actually listening, with `--dart-define-from-file`.  
It is not always the root URI in the server configuration (`.../MultiPurposeAuthSite`).  
The following files are for local sites started as in CHEATSHEET.md section 5 (the endpoints are at the root).

- mpas.core.json : net10.0 (https://localhost:44300)
- mpas.netfx.json : net48 on IIS Express (https://localhost:44302)

Without the file, `https://localhost:44300` is used.  
When net48 is started from Visual Studio, the project setting (`IISUrl`) is `https://localhost:44300/MultiPurposeAuthSite/`.  
In that case, write the URL without the trailing slash in your own file (not verified).  
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

To try background notifications (clicking the OS notification), open the app in your usual Chrome.  
In the Chrome started by `flutter run -d chrome` (a temporary profile), the click did not reach the app.

    flutter run -d web-server --web-port 5610 --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json

## Installing it as a PWA
`flutter run` does not generate the manifest, so the install check fails there  
(DevTools reports "no name", "invalid display" and "no icon" at once, although `manifest.json` itself is correct).  
Serve the built output instead.

    flutter build web --dart-define-from-file=firebase_web.json --dart-define-from-file=mpas.core.json
    cd build/web
    python -m http.server 5610

Open `http://localhost:5610/` in your usual Chrome and install it from the address bar.  
The `redirect_uri` is the same, so sign-in works as it is.

Whether a message arrives in the page (Message Stream) or as an OS notification depends on  
whether the app window is visible. This is the same for an installed PWA.  
Clicking the notification opens the app window, not a browser tab.

## Using it from other devices (HTTPS)
On the same PC, `localhost` is treated as a secure context, so HTTPS is not needed.  
Using the PWA from another device (such as a smartphone) needs all of the following:

1. Serve the PWA over HTTPS with a certificate the device trusts.
2. Run MultiPurposeAuthSite over HTTPS with a certificate the device trusts  
   (the ASP.NET Core development certificate is not trusted on the device).
3. Register the PWA's URL as the `redirect_uri` of `AuthenticationDevice_Web` on the server,  
   and pass the same URL to the app with `MPAS_WEB_REDIRECT_URI`.
4. On iOS, Web Push works only for a PWA added to the Home Screen (Safari 16.4 or later).
