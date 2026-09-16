{{flutter_js}}
{{flutter_build_config}}

// Flutter 自身の service worker（非推奨）は登録しない（#205）。
//
// Flutter が生成する既定の flutter_bootstrap.js は serviceWorkerSettings を渡し、
// flutter_service_worker.js を scope "/" に登録する。
// Web Push を受ける firebase-messaging-sw.js も scope "/" に登録するため、
// 後から登録した方に置き換わってしまう。
_flutter.loader.load();
