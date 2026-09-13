// Web Push を受ける service worker（#205）。
//
// Flutter（Dart）の外で動くため、Firebase の JS SDK をここで読み込む。
// 版は、firebase_core_web が読み込む版に合わせる
// （firebase_core_web の firebase_sdk_version.dart の supportedFirebaseJsSdkVersion）。
//   firebase_core_web 3.10.0 → 12.17.0
//
// 構成は --dart-define では渡せないので、登録時の URL のクエリ文字列で受け取る
// （lib/configs/app_firebase_web.dart の serviceWorkerPath）。

importScripts('https://www.gstatic.com/firebasejs/12.17.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/12.17.0/firebase-messaging-compat.js');

const params = new URL(self.location.href).searchParams;
const config = {
  apiKey: params.get('apiKey'),
  appId: params.get('appId'),
  messagingSenderId: params.get('messagingSenderId'),
  projectId: params.get('projectId'),
};

if (config.apiKey && config.appId && config.messagingSenderId && config.projectId) {
  firebase.initializeApp(config);
  const messaging = firebase.messaging();

  // タブが前面に無いときに届いたメッセージ。
  // notification を含むメッセージ（認証サイトの FcmService が送る形）は、
  // SDK が自動で通知を表示する。ここで表示すると二重になるので、記録だけにする。
  messaging.onBackgroundMessage((payload) => {
    console.log('[firebase-messaging-sw] background message', payload);
  });
} else {
  console.warn('[firebase-messaging-sw] Firebase の構成がクエリ文字列に無いため、初期化しない。');
}

// 通知をクリックしたら、開いているアプリのタブを前面に出す（無ければ開く）。
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const client of list) {
        if ('focus' in client) {
          return client.focus();
        }
      }
      return clients.openWindow('./');
    })
  );
});
