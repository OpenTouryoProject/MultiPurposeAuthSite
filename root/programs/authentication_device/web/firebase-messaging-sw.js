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

// 通知のクリック（#205 増分 3）。
//
// **Firebase の SDK より先に登録する。**
// SDK は firebase.messaging() の初期化時に自分の notificationclick を登録し、
// FCM の通知（notification.data.FCM_MSG を持つもの）では stopImmediatePropagation() を呼ぶ。
// さらに、開く先（fcmOptions.link / click_action）が無い通知は、閉じるだけで何もしない
// （認証サイトの FcmService が送る通知は、これに当たる）。
// そこで、ここで先に受け取り、通知の中身を URL のクエリに載せてアプリを開く。
// アプリは起動時に URL を読み、詳細画面を開く（lib/components/web_push_click.dart）。
//   確認した SDK : firebase-messaging-compat.js 12.17.0
//
// 注意 : auth_req_id などが、タブの URL（履歴）に載る。認証デバイスはテスト用なので許容している。
//
// 注意 : flutter run -d chrome が起動する Chrome（一時プロファイルの別インスタンス）では、
//        OS の通知をクリックしても、この処理が呼ばれなかった（#205 で確認）。
//        普段の Chrome で開く（flutter run -d web-server で配信）と、呼ばれて詳細画面まで開けた。
self.addEventListener('notificationclick', (event) => {
  const payload = event.notification && event.notification.data && event.notification.data.FCM_MSG;
  if (!payload) {
    // FCM 以外の通知は触らない。
    return;
  }

  // SDK の notificationclick を動かさない（動いても、閉じるだけで何もしない）。
  event.stopImmediatePropagation();
  event.notification.close();

  // service worker の場所 = アプリのルート（クエリは付けない）
  const url = new URL('./', self.location.href);
  const notification = payload.notification || {};
  url.searchParams.set('push_title', notification.title || '');
  url.searchParams.set('push_body', notification.body || '');
  const data = payload.data || {};
  for (const key of Object.keys(data)) {
    url.searchParams.set('push_data_' + key, data[key]);
  }

  event.waitUntil((async () => {
    const list = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of list) {
      if (new URL(client.url).origin !== self.location.origin) {
        continue;
      }
      // **先に前面に出す。** focus は、通知のクリックから短い時間しか許されない。
      //   navigate はページの読み込み完了を待つ（デバッグ実行では数十秒かかる）ので、
      //   その後に focus すると、許される時間を過ぎて失敗しうる。
      try {
        await client.focus();
      } catch (e) {
        console.log('[firebase-messaging-sw] タブを前面に出せない', e);
      }
      try {
        // 開いているアプリのタブを、通知の中身を載せた URL に移す。
        // navigate は、この service worker が制御しているタブでしか使えない（それ以外は例外）。
        const moved = await client.navigate(url.href);
        if (moved) {
          return moved;
        }
      } catch (e) {
        console.log('[firebase-messaging-sw] タブを移せないため、新しく開く', e);
      }
    }
    console.log('[firebase-messaging-sw] 開いているタブを使えないため、openWindow で開く');
    return clients.openWindow(url.href);
  })());
});

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
    // 中身（auth_req_id など）は出さない。タイトルだけ。
    const title = payload && payload.notification ? payload.notification.title : null;
    console.log('[firebase-messaging-sw] background message', title);

    // ---------------------------------------------------------------------
    // **調査用（一時）: なぜ「バックグラウンド」と判定されたのかを見る。**
    //
    // 2FA の通知が、PWA のウィンドウの状態にかかわらず OS の通知になる、という観測がある
    // （ANALYSIS.md 8 節 16）。判定は SDK が
    //   clients.matchAll({ type: 'window', includeUncontrolled: true }) の中に
    //   visibilityState === 'visible' のクライアントがあるか
    // だけで行うので、届いた瞬間の一覧を出せば分かる。**同じ引数で取る。**
    //
    // 分かったら、このブロックは消すこと。
    // URL はパスまでにする（クエリに push_data_* が載ることがあるため）。
    // ---------------------------------------------------------------------
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      console.log('[firebase-messaging-sw] 調査 : title=' + title
        + ' / clients=' + list.length + ' / scope=' + self.registration.scope);
      list.forEach((client, i) => {
        let where = client.url;
        try {
          const u = new URL(client.url);
          where = u.origin + u.pathname;
        } catch (e) { /* そのまま */ }
        console.log('  [' + i + '] visibilityState=' + client.visibilityState
          + ' focused=' + client.focused
          + ' type=' + client.type
          + ' url=' + where);
      });
    });
  });
} else {
  console.warn('[firebase-messaging-sw] Firebase の構成がクエリ文字列に無いため、初期化しない。');
}
