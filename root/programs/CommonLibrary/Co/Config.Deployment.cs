//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
//**********************************************************************************

#region Apache License
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License. 
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion

//**********************************************************************************
//* クラス名        ：Config
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）の 配備・基盤
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/23  玄人 幸道         新規（Config.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Data;

using System;

using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Config（配備・基盤）</summary>
    public partial class Config
    {
        #region 配備・基盤

        #region Proxy

        /// <summary>
        /// UseInternetProxy
        /// </summary>
        public static bool UseInternetProxy
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("UseInternetProxy"));
            }
        }

        /// <summary>
        /// InternetプロキシURL
        /// </summary>
        public static string InternetProxyURL
        {
            get
            {
                return GetConfigParameter.GetConfigValue("InternetProxyURL");
            }
        }

        /// <summary>
        /// InternetプロキシUID
        /// </summary>
        public static string InternetProxyUID
        {
            get
            {
                return GetConfigParameter.GetConfigValue("InternetProxyUID");
            }
        }

        /// <summary>
        /// InternetプロキシPWD
        /// </summary>
        public static string InternetProxyPWD
        {
            get
            {
                return GetConfigParameter.GetConfigValue("InternetProxyPWD");
            }
        }

        /// <summary>
        /// UseIntranetProxy
        /// </summary>
        public static bool UseIntranetProxy
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("UseIntranetProxy"));
            }
        }

        /// <summary>
        /// IntranetプロキシURL
        /// </summary>
        public static string IntranetProxyURL
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IntranetProxyURL");
            }
        }

        /// <summary>
        /// IntranetプロキシUID
        /// </summary>
        public static string IntranetProxyUID
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IntranetProxyUID");
            }
        }

        /// <summary>
        /// IntranetプロキシPWD
        /// </summary>
        public static string IntranetProxyPWD
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IntranetProxyPWD");
            }
        }

        /// <summary>
        /// UseDebugProxy
        /// </summary>
        public static bool UseDebugProxy
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("UseDebugProxy"));
            }
        }

        /// <summary>
        /// DebugProxyURL
        /// </summary>
        public static string DebugProxyURL
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DebugProxyURL");
            }
        }

        /// <summary>
        /// DebugProxyUID
        /// </summary>
        public static string DebugProxyUID
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DebugProxyUID");
            }
        }

        /// <summary>
        /// DebugProxyPWD
        /// </summary>
        public static string DebugProxyPWD
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DebugProxyPWD");
            }
        }

        #endregion

        #region HTTPS・逆プロキシ（#279）

        //  **本番でだけ有効にしたい設定を「コメントアウトして置いておく」と、
        //    環境を移すときにソースを書き換えることになる。**
        //    Open棟梁 の MVC_Sample に倣い、設定で切り替える形にした（#279 / 上流 #541・#549）。
        //
        //  **いずれも net10.0 版だけの設定である。**
        //    net48 版は `Web.config` の `<httpCookies>` / `<rewrite>` などで行う。
        //    **`_app.config` にキーを置いていない**のは、`DataProtectionKeyPath`（#251）と同じ理由。
        //
        //  **既定値は、いずれも従来どおりの動作**である。

        /// <summary>HTTP を HTTPS へリダイレクトするか（#279）</summary>
        /// <remarks>
        /// **既定は off。** 平文 HTTP で動かす環境（疎通確認や、
        /// TLS を前段のリバース プロキシで終端する構成）でリダイレクトすると、
        /// **到達できなくなる**ため。TLS を自分で終端するなら `on` にする。
        ///
        /// **on にするだけでは足りない。リダイレクト先のポートも要る。**
        /// 決められないと、ミドルウェアは警告を出すだけで素通りする。
        /// </remarks>
        public static bool UseHttpsRedirection
        {
            get
            {
                return (GetConfigParameter.GetConfigValue("UseHttpsRedirection") ?? "")
                    .ToLower() == "on";
            }
        }

        /// <summary>Cookie に Secure 属性を必ず付けるか（#279）</summary>
        /// <remarks>
        /// **設定キーは `CookieSecurePolicy`**（`always` のときだけ true）。
        ///
        /// **既定は空＝各 Cookie の設定に従う。**
        /// **平文 HTTP の環境で `always` にすると、Cookie が送られずサインインできなくなる**
        /// （AntiForgery の Cookie も返らないので、
        /// 症状は「サインイン画面は出るが POST が 400」になる）。
        /// </remarks>
        public static bool CookieSecurePolicyAlways
        {
            get
            {
                return (GetConfigParameter.GetConfigValue("CookieSecurePolicy") ?? "")
                    .ToLower() == "always";
            }
        }

        /// <summary>転送ヘッダ（X-Forwarded-Proto / -For）を取り込むか（#279）</summary>
        /// <remarks>
        /// **リバース プロキシで TLS を終端すると、アプリから見た接続は HTTP になる。**
        /// 利用者のブラウザは HTTPS で繋いでいるのに `Request.IsHttps` は false のままで、
        /// **Secure 属性が付かず、生成する絶対 URL も http になる。**
        ///
        /// **既定は off。** 素の HTTP で動かす環境では、
        /// **転送ヘッダを誰でも付けられる（＝ クライアントが詐称できる）**ため。
        /// </remarks>
        public static bool UseForwardedHeaders
        {
            get
            {
                return (GetConfigParameter.GetConfigValue("UseForwardedHeaders") ?? "")
                    .ToLower() == "on";
            }
        }

        /// <summary>信用する前段のアドレス（#279。カンマ区切り。空なら範囲を制限しない）</summary>
        /// <remarks>
        /// **既定ではループバックからの転送しか信用しない。**
        /// コンテナや Kubernetes では前段が別アドレスになるため、
        /// **指定しないとヘッダが黙って捨てられ、何も起きない。**
        /// **「on にしたのに直らない」の原因はほぼこれである。**
        /// </remarks>
        public static string ForwardedHeadersKnownProxies
        {
            get
            {
                return GetConfigParameter.GetConfigValue("ForwardedHeadersKnownProxies");
            }
        }

        #endregion

        #region データ保護の鍵

        /// <summary>
        /// DataProtection の鍵の置き場（#251。C-13）
        /// </summary>
        /// <remarks>
        /// **net10.0 版だけで使う。** net48 版は machineKey の話で、別。
        ///
        /// **指定しなければ、従来どおり `%LOCALAPPDATA%` 配下**（コンテナでは揮発）。
        /// **指定すると、そこに鍵リングを置く**ので、
        /// **再起動やコンテナの作り直しでもサインインが切れない。**
        ///
        /// **鍵そのものは書かない**（net48 の `machineKey` との違い）。
        /// **鍵は自動生成・自動ローテーションされる。共有するのは置き場である。**
        ///
        /// **効くのは「画面のセッション」**（認証 Cookie / AntiForgery /
        /// メール確認・パスワード リセットのリンク）。
        /// **access_token / id_token・PPID・認可コード・refresh_token には影響しない。**
        ///
        /// **鍵リングは平文の XML。** 置き場の保護は運用側の責任。
        /// </remarks>
        public static string DataProtectionKeyPath
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DataProtectionKeyPath");
            }
        }

        #endregion

        #region セッション

        /// <summary>セッションの置き場（net10.0 版だけ。#256）</summary>
        /// <remarks>
        /// **`mem`（既定） / `sql` / `redis`。**
        /// **書かなければ `mem`**（＝ 従来どおり。プロセス内のメモリ）。
        ///
        /// **net48 版は読まない。** あちらは `Web.config` の `sessionState` で選ぶ。
        ///
        /// | 値 | 置き場 | 複数インスタンス |
        /// |---|---|---|
        /// | `mem` | プロセス内 | **共有されない**（単一インスタンス向け） |
        /// | `sql` | SQL Server のテーブル | 共有される。`Create_SessionCache.sql` を流しておく |
        /// | `redis` | Redis | 共有される。**`UserStoreType` の方言に依らない** |
        ///
        /// **`UserStoreType` と同じ流儀**にしてある（`EnumSessionStoreType`）。
        /// **Oracle / PostgreSQL 用の `IDistributedCache` は標準に無い**ので、
        /// **それらのストアで複数インスタンスにするなら `redis` を使う。**
        /// </remarks>
        public static EnumSessionStoreType SessionStoreType
        {
            get
            {
                // **キーが無いと null が返る。** `UserStoreType` と違い、
                //   **このキーは雛形以外では無いことがある**（既存の配備）ので、
                //   そのまま `ToUpper()` すると、起動時に落ちる。
                string sessionStoreType = GetConfigParameter.GetConfigValue("SessionStoreType");

                switch ((sessionStoreType ?? "").ToUpper())
                {
                    case "MEM":
                        return EnumSessionStoreType.Memory;
                    case "SQL":
                        return EnumSessionStoreType.SqlServer;
                    case "REDIS":
                        return EnumSessionStoreType.Redis;
                    default:
                        // **書かなければプロセス内**（＝ 従来どおり）。
                        return EnumSessionStoreType.Memory;
                }
            }
        }

        /// <summary>セッションの置き場への接続文字列（net10.0 版だけ。#256）</summary>
        /// <remarks>
        /// **`SessionStoreType` で意味が変わる。**
        ///
        /// | `SessionStoreType` | 書くもの |
        /// |---|---|
        /// | `mem` | **要らない**（読まない） |
        /// | `sql` | **SQL Server の接続文字列。** `ConnectionString_SQL` と同じでよいが、別の DB にもできる |
        /// | `redis` | **Redis の接続文字列**（`localhost:6379` など） |
        ///
        /// **`UserStoreType` のように方言ごとに分けていない**のは、
        /// **`SessionStoreType` が置き場を一意に決める**ためである。
        /// </remarks>
        public static string SessionStoreConnectionString
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SessionStoreConnectionString");
            }
        }

        #endregion

        #region CORS

        /// <summary>CORS で追加して許可するオリジン（任意。#265）</summary>
        /// <remarks>
        /// **空でよい。** 既定では、**構成ファイルに登録された public クライアントの
        /// `redirect_uri_*` からオリジンを導く**（`CmnEndpoints.GetCorsAllowedOrigins`）。
        /// **ここは、その導出で拾えないものを足すための口**である。
        ///
        /// **区切りは空白かカンマ。** 値はオリジン（`https://host:port`）で書く。
        /// **末尾の `/` は付けない**（CORS の比較はオリジン同士で、パスを含まない）。
        ///
        /// **`*` は書かないこと。** 書いても拒否する（`ProductionCheck` が警告する）。
        /// </remarks>
        public static string CorsAllowedOrigins
        {
            get
            {
                return GetConfigParameter.GetConfigValue("CorsAllowedOrigins");
            }
        }

        #endregion

        #endregion
    }
}