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
//* クラス名        ：CmnDPoP
//* クラス日本語名  ：DPoP の証明（RFC 9449）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#311 の段階 1）
//*  2026/10/21  玄人 幸道         リソース側の照合（ath / jkt / スキーム）を追加（#311 の段階 2）
//*  2026/10/22  玄人 幸道         使った証明を記録して使い回しを断る（#311 の段階 3）
//*  2026/10/22  玄人 幸道         nonce・dpop_jkt を追加（#311 の段階 4）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Log;

using System;
using System.Security.Cryptography;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>
    /// CmnDPoP
    /// **DPoP の証明（proof）を検証し、鍵の指紋（`jkt`）を返す**（#311 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **DPoP は「鍵を持っていること」を要求ごとに示させる**仕組みである（RFC 9449）。
    /// **mTLS（RFC 8705）と違い、証明書を配れない相手**
    /// （**SPA / ネイティブ ＝ パブリック クライアント**）**にも使える。**
    ///
    /// | | |
    /// |---|---|
    /// | **何が来るか** | **`DPoP` ヘッダに、短い JWT**（**証明**）。**公開鍵はその JWT のヘッダ（`jwk`）に入っている** |
    /// | **何を返すか** | **`jkt`**（**その公開鍵の指紋**。RFC 7638）。**`cnf.jkt` としてトークンに書く** |
    /// | **外へ取りに行かない** | **鍵が要求の中に在る**ので、**`jwks_uri` のような取得が要らない**（#309 で踏んだ同期の詰まりを踏まない） |
    ///
    /// **段階 1 で見るのはここまで**である。
    ///
    /// | | 段階 |
    /// |---|---|
    /// | **`/token` で証明を受け、`cnf.jkt` を書く** | **段階 1**（この型） |
    /// | **保護されたリソースで照合する**（`ath` / `Authorization: DPoP`） | 段階 2 |
    /// | **`jti` の使い回しを拒む**（記録と掃除が要る） | **段階 3**（`DPoPProofProvider`） |
    /// | **`DPoP-Nonce`・認可要求の `dpop_jkt`・`refresh_token` の縛り** | **段階 4** |
    /// </remarks>
    public class CmnDPoP
    {
        #region 定数

        /// <summary>DPoP の証明を運ぶ要求ヘッダ（RFC 9449 §4）</summary>
        public const string HttpHeader = "DPoP";

        /// <summary>token_type（RFC 9449 §5）と Authorization のスキーム（§7）</summary>
        public const string TokenType = "DPoP";

        /// <summary>証明の typ ヘッダ（RFC 9449 §4.2）</summary>
        public const string Typ = "dpop+jwt";

        /// <summary>JWS のヘッダの項目名（`typ`）</summary>
        /// <remarks>
        /// **`JwtConst` には `typ` が無い**（`JWS_Header.typ` の property は在る）。
        /// **ここで名前を持つ**（**読み取りはヘッダの JSON から行う**ため）。
        /// </remarks>
        private const string TypHeader = "typ";

        /// <summary>証明のヘッダに入る公開鍵（RFC 9449 §4.2）</summary>
        public const string JwkHeader = "jwk";

        /// <summary>cnf のメンバ（RFC 9449 §6）</summary>
        public const string Jkt = "jkt";

        /// <summary>HTTP メソッド（RFC 9449 §4.2）</summary>
        public const string Htm = "htm";

        /// <summary>HTTP の宛先（RFC 9449 §4.2）</summary>
        public const string Htu = "htu";

        /// <summary>証明が使えないときの error（RFC 9449 §5）</summary>
        public const string InvalidDPoPProof = "invalid_dpop_proof";

        /// <summary>`iat` が古すぎるとみなす線</summary>
        /// <remarks>
        /// **証明は要求ごとに作られる**ので、**長く遡る必要は無い。**
        /// **狭すぎると時計のズレで落ちる**ため、**少し広く取っている。**
        ///
        /// **使い回しをここで止めるつもりはない** —
        /// **止めるのは `jti` の記録（段階 3。`DPoPProofProvider`）と
        /// `DPoP-Nonce`（段階 4）である。**
        /// **設定キーは増やしていない**（#310 の掃除の間隔と同じ扱い）。
        /// </remarks>
        private static readonly TimeSpan PastWindow = TimeSpan.FromMinutes(5);

        /// <summary>`iat` が未来すぎるとみなす線</summary>
        /// <remarks>**未来は時計のズレの分だけ**許す（**作り置きを許さない**）。</remarks>
        private static readonly TimeSpan FutureWindow = TimeSpan.FromMinutes(1);

        /// <summary>1 つの証明が通りうる長さ（#311 の段階 3）</summary>
        /// <remarks>
        /// **窓の中なら、同じ証明が何度でも通りうる** —
        /// **だから、台帳はこの長さだけ持てばよい**（`DPoPProofProvider`）。
        ///
        /// **「過去 ＋ 未来」である**ことに意味が在る。
        /// **`iat` が 1 分先の証明は、作られてから 6 分後まで窓の中**にいる
        /// （**`iat` が「今 − 5 分」を上回っている間**）。
        /// **過去の分だけで消すと、その差だけ使い回しが通る。**
        ///
        /// **台帳の側に長さを書かない** — **片方だけ直して食い違うのを防ぐ。**
        /// </remarks>
        public static readonly TimeSpan ProofReplayWindow =
            CmnDPoP.PastWindow + CmnDPoP.FutureWindow;

        /// <summary>秘密鍵が混ざっていないかを見る項目（RFC 7517 / 7518）</summary>
        /// <remarks>
        /// **RFC 9449 §4.3 : `jwk` に秘密鍵が入っていてはならない。**
        /// **入っていたら、そのまま検証して通してはいけない**
        /// （**鍵の取り違えだけでなく、秘密鍵を送らせる実装の誤りを見逃す**ことになる）。
        /// </remarks>
        private static readonly string[] PrivateMembers = new string[]
        {
            "d", "p", "q", "dp", "dq", "qi", "oth", "k"
        };

        /// <summary>`ath`（access_token の指紋。RFC 9449 §4.2）</summary>
        public const string Ath = "ath";

        /// <summary>認可要求で鍵を先に申告するパラメタ（RFC 9449 §10）</summary>
        /// <remarks>
        /// **`dpop_jkt`** は、**認可要求の時点で「このコードは、この鍵でしか引き換えない」と言う**ための値である
        /// （**値は `jkt` と同じ** ＝ 公開鍵の指紋）。
        ///
        /// **コードを盗んで `/token` に持ち込む筋**を塞ぐ —
        /// **PKCE が `code_verifier` で塞ぐのと同じ所**を、**鍵で塞ぐ。**
        /// </remarks>
        public const string JktParam = "dpop_jkt";

        #endregion

        #region 口の URL（`htu` の期待値）

        /// <summary>`/token` の宛先</summary>
        /// <remarks>
        /// **設定から作る。** **要求の `Host` ヘッダを信じない** —
        /// **信じると、`htu` の照合が「相手の言うとおり」になって意味を失う。**
        /// **この製品は発行者の URL を設定で持っている**ので、そこから作れる。
        /// </remarks>
        public static string TokenEndpointUri
        {
            get { return CmnDPoP.EndpointUri(Config.OAuth2TokenEndpoint); }
        }

        /// <summary>この要求の口の宛先を、設定から引く（#311 の段階 2）</summary>
        /// <param name="requestPath">要求のパス（`/MultiPurposeAuthSite/userinfo` など）</param>
        /// <returns>設定から作った URL（当てが無ければ空）</returns>
        /// <remarks>
        /// **要求から使うのはパスだけ**である。**`Host` ヘッダは見ない** —
        /// **見ると `htu` の照合が「相手の言うとおり」になって意味を失う。**
        /// **URL は設定のルートから作る。**
        ///
        /// **口のパスは、すべて設定キーで持っている**（**ルーティングも同じ値を見ている**）ので、
        /// **ここに文字列リテラルを置かない** — **ルートと食い違うと、黙って照合が落ちる。**
        ///
        /// **仮想ディレクトリの下に配備されることが在る**ので、**末尾の一致で見る。**
        /// **当てが無ければ空を返す** — **呼び出し側（照合）は、空の `htu` では通らない。**
        /// </remarks>
        public static string EndpointUriOf(string requestPath)
        {
            if (string.IsNullOrEmpty(requestPath))
            {
                return "";
            }

            string[] paths = new string[]
            {
                Config.OAuth2TokenEndpoint,
                Config.OAuth2UserInfoEndpoint,
                Config.DcrRegistrationEndpoint,
                Config.CibaPushResultEndpoint,
                Config.SetDeviceTokenWebAPI,
                Config.TwoFactorPushResultEndpoint
            };

            foreach (string path in paths)
            {
                if (!string.IsNullOrEmpty(path)
                    && requestPath.EndsWith(path, StringComparison.OrdinalIgnoreCase))
                {
                    return CmnDPoP.EndpointUri(path);
                }
            }

            return "";
        }

        /// <summary>口の URL（設定のルート ＋ 口のパス）</summary>
        /// <param name="path">口のパス（設定キーの値）</param>
        /// <returns>URL</returns>
        /// <remarks>
        /// **口のパスは、すべて設定キーで持っている**（ルーティングも同じ値を見ている）。
        /// **ここに文字列リテラルを置かない** — **ルートと食い違うと、黙って照合が落ちる。**
        /// </remarks>
        private static string EndpointUri(string path)
        {
            return Config.OAuth2AuthorizationServerEndpointsRootURI + path;
        }

        #endregion

        #region Authorization ヘッダ

        /// <summary>`Authorization` ヘッダから、トークンとスキームを読む（#311 の段階 2）</summary>
        /// <param name="authorizationHeader">`Authorization` ヘッダ</param>
        /// <param name="token">out : トークン</param>
        /// <param name="isDPoP">out : **`DPoP` スキームで来たか**</param>
        /// <returns>トークンが読めれば true</returns>
        /// <remarks>
        /// **`DPoP` スキーム**（RFC 9449 §7.1）**と、従来の `Bearer`** の両方を読む。
        /// **`Bearer` の読み取りは、これまでと同じ口に委ねる**（`AuthenticationHeader.GetCredentials`） —
        /// **大文字小文字や空白の扱いを、ここで作り直さない。**
        ///
        /// **スキームを呼び出し側に返す**のが要点である。
        /// **`cnf.jkt` で縛ったトークンを `Bearer` で出してきた要求は、断らなければならない**
        /// （**縛りを「使う側の出し方」で外せてはいけない**）。
        /// </remarks>
        public static bool GetToken(string authorizationHeader, out string token, out bool isDPoP)
        {
            token = "";
            isDPoP = false;

            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return false;
            }

            string prefix = CmnDPoP.TokenType + " ";

            if (authorizationHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                token = authorizationHeader.Substring(prefix.Length).Trim();
                isDPoP = true;

                return !string.IsNullOrEmpty(token);
            }

            return AuthenticationHeader.GetCredentials(authorizationHeader, out token);
        }

        #endregion

        #region リソース側の照合（#311 の段階 2）

        /// <summary>保護されたリソースで、証明とトークンの結び付きを照合する（#311 の段階 2）</summary>
        /// <param name="proof">`DPoP` ヘッダの値（**`DPoP` スキームで来ていないなら空**）</param>
        /// <param name="htm">この要求の HTTP メソッド（**大文字**）</param>
        /// <param name="htu">この口の宛先</param>
        /// <param name="accessToken">提示された access_token</param>
        /// <param name="boundJkt">トークンに書かれた `cnf.jkt`</param>
        /// <param name="error">out : error（`invalid_token`、または `use_dpop_nonce`）</param>
        /// <param name="errDescription">out : 断る理由</param>
        /// <returns>使ってよければ true</returns>
        /// <remarks>
        /// **段階 1 の検証に、2 つ足す**（RFC 9449 §7.1）。
        ///
        /// | 足すもの | なぜ |
        /// |---|---|
        /// | **`ath` が、提示されたトークンの指紋と一致すること** | **別のトークンに付けた証明を使い回させない** |
        /// | **証明の鍵が、トークンの `cnf.jkt` と同じであること** | **これが「持ち主である」ことの確認**である |
        ///
        /// **`ath` は access_token の SHA-256 を BASE64URL したもの**（§4.2）。
        ///
        /// **`error` を返すのは、`use_dpop_nonce` を区別するため**である（§9。#311 の段階 4）。
        /// **それ以外は `invalid_token`**（**この口の従来の断り方**）。
        /// </remarks>
        public static bool VerifyForResource(
            string proof, string htm, string htu,
            string accessToken, string boundJkt, out string error, out string errDescription)
        {
            error = OAuth2AndOIDCConst.invalid_token;
            errDescription = "";

            if (string.IsNullOrEmpty(proof))
            {
                errDescription = "A DPoP proof is required for this access token.";
                return CmnDPoP.Deny(errDescription);
            }

            if (!CmnDPoP.Verify(proof, htm, htu, CmnDPoP.PurposeRs,
                out string jkt, out string proofError, out errDescription))
            {
                //  **nonce が要るときだけ、その error を返す**（RFC 9449 §9。#311 の段階 4）。
                //    **それ以外は `invalid_token`** — **証明の中身は、要求元に教えない。**
                if (proofError == CmnDPoP.UseDPoPNonce)
                {
                    error = CmnDPoP.UseDPoPNonce;
                }

                return false;
            }

            if (!string.Equals(jkt, boundJkt, StringComparison.Ordinal))
            {
                errDescription = "The DPoP proof was signed with another key.";
                return CmnDPoP.Deny(errDescription);
            }

            JObject payload = CmnEndpoints.TryReadJwtPayload(proof);
            string ath = (payload == null) ? null : (string)payload[CmnDPoP.Ath];

            if (!string.Equals(ath, CmnDPoP.Thumbprint(accessToken), StringComparison.Ordinal))
            {
                errDescription = "The ath of the DPoP proof does not match the access token.";
                return CmnDPoP.Deny(errDescription);
            }

            return true;
        }

        /// <summary>文字列の指紋（`ath` の値。RFC 9449 §4.2）</summary>
        /// <param name="value">access_token</param>
        /// <returns>BASE64URL(SHA-256(value))。空なら空</returns>
        public static string Thumbprint(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "";
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                return CustomEncode.ToBase64UrlString(
                    sha256.ComputeHash(CustomEncode.StringToByte(value, CustomEncode.us_ascii)));
            }
        }

        #endregion

        #region nonce（#311 の段階 4）

        /// <summary>`DPoP-Nonce` 応答ヘッダ（RFC 9449 §8）</summary>
        public const string NonceHeader = "DPoP-Nonce";

        /// <summary>証明の `nonce`（RFC 9449 §8）</summary>
        public const string Nonce = "nonce";

        /// <summary>nonce が要る / 通らないときの error（RFC 9449 §8 / §9）</summary>
        public const string UseDPoPNonce = "use_dpop_nonce";

        /// <summary>nonce の用途（`/token` 側。RFC 9449 §8）</summary>
        /// <remarks>
        /// **`/token` の nonce と、保護されたリソースの nonce は別物**である（§9）。
        /// **用途を混ぜると、片方で貰った nonce がもう片方で通ってしまう。**
        /// </remarks>
        public const string PurposeAs = "as";

        /// <summary>nonce の用途（保護されたリソース側。RFC 9449 §9）</summary>
        public const string PurposeRs = "rs";

        /// <summary>nonce が変わる間隔</summary>
        /// <remarks>
        /// **1 つ前の時間帯の nonce も受け付ける**ので、**使える長さは 5〜10 分**である。
        /// **設定キーは増やしていない**（窓や掃除の間隔と同じ扱い）。
        /// </remarks>
        private static readonly TimeSpan NonceSlot = TimeSpan.FromMinutes(5);

        /// <summary>nonce を作る鍵</summary>
        /// <remarks>
        /// **設定（`DPoPNonceSecret`）が空なら、プロセスごとのランダムな値**である。
        /// **インスタンスを増やす配備では、設定すること**（`Config.DPoPNonceSecret` の注）。
        /// </remarks>
        private static readonly byte[] NonceKey = CmnDPoP.CreateNonceKey();

        /// <summary>nonce を要求する配備か</summary>
        public static bool NonceRequired
        {
            get { return Config.EnableDPoPNonce; }
        }

        /// <summary>いまの nonce（RFC 9449 §8）</summary>
        /// <param name="purpose">用途（`PurposeAs` / `PurposeRs`）</param>
        /// <returns>nonce</returns>
        /// <remarks>
        /// **台帳を持たない** — **「鍵 ＋ 用途 ＋ 時間帯」から計算する。**
        /// **発行したものを覚えておく必要が無い**ので、**インスタンスを増やしても効く**
        /// （**同じ鍵を配る限り**）。
        ///
        /// **照合は、いまと 1 つ前の時間帯の値と比べるだけ**である —
        /// **相手から来た文字列を解析しない**（**解析する物が無い**）。
        /// </remarks>
        public static string CurrentNonce(string purpose)
        {
            return CmnDPoP.NonceOfSlot(purpose, CmnDPoP.CurrentSlot());
        }

        /// <summary>チャレンジに載せる nonce（要らない配備なら null）</summary>
        /// <param name="isDPoP">**`DPoP` スキームで来たか**</param>
        /// <returns>nonce（null なら付けない）</returns>
        /// <remarks>
        /// **`Bearer` で来た要求には付けない** — **DPoP の話をしていない相手**である。
        /// </remarks>
        public static string NonceForChallenge(bool isDPoP)
        {
            if (!CmnDPoP.NonceRequired || !isDPoP)
            {
                return null;
            }

            return CmnDPoP.CurrentNonce(CmnDPoP.PurposeRs);
        }

        /// <summary>証明の `nonce` を見る（#311 の段階 4）</summary>
        /// <param name="payload">証明のペイロード</param>
        /// <param name="purpose">用途（`PurposeAs` / `PurposeRs`）</param>
        /// <param name="errDescription">out : 断る理由</param>
        /// <returns>続けてよければ true</returns>
        /// <remarks>
        /// **要求しない配備では、何も見ない**（**既定の挙動を変えない**）。
        /// **`nonce` が無い場合も、古い場合も、同じ `use_dpop_nonce` で断る** —
        /// **クライアントの出直し方は、どちらも同じ**である（§8）。
        /// </remarks>
        private static bool CheckNonce(JObject payload, string purpose, out string errDescription)
        {
            errDescription = "";

            if (!CmnDPoP.NonceRequired || string.IsNullOrEmpty(purpose))
            {
                return true;
            }

            string nonce = (payload == null) ? null : (string)payload[CmnDPoP.Nonce];

            if (string.IsNullOrEmpty(nonce))
            {
                errDescription = "The DPoP proof must have a nonce.";
                return CmnDPoP.Deny(errDescription);
            }

            long slot = CmnDPoP.CurrentSlot();

            //  **1 つ前の時間帯も受け付ける** — **境目で断らない**ため。
            if (string.Equals(nonce, CmnDPoP.NonceOfSlot(purpose, slot), StringComparison.Ordinal)
                || string.Equals(nonce, CmnDPoP.NonceOfSlot(purpose, slot - 1), StringComparison.Ordinal))
            {
                return true;
            }

            errDescription = "The nonce of the DPoP proof is not acceptable.";
            return CmnDPoP.Deny(errDescription);
        }

        /// <summary>いまの時間帯</summary>
        /// <returns>時間帯の番号</returns>
        private static long CurrentSlot()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                / (long)CmnDPoP.NonceSlot.TotalSeconds;
        }

        /// <summary>その時間帯の nonce</summary>
        /// <param name="purpose">用途</param>
        /// <param name="slot">時間帯の番号</param>
        /// <returns>nonce</returns>
        private static string NonceOfSlot(string purpose, long slot)
        {
            using (HMACSHA256 hmac = new HMACSHA256(CmnDPoP.NonceKey))
            {
                return CustomEncode.ToBase64UrlString(hmac.ComputeHash(
                    CustomEncode.StringToByte(
                        purpose + "." + slot.ToString(), CustomEncode.UTF_8)));
            }
        }

        /// <summary>nonce を作る鍵を決める</summary>
        /// <returns>鍵</returns>
        /// <remarks>
        /// **設定が在ればそれを使い、無ければランダムに作る。**
        /// **ランダムの場合、再起動で前の nonce が通らなくなる** —
        /// **クライアントは `use_dpop_nonce` で新しい値を貰ってやり直す**ので、
        /// **止まりはしない**（**1 往復増えるだけ**）。
        /// </remarks>
        private static byte[] CreateNonceKey()
        {
            string secret = Config.DPoPNonceSecret;

            if (!string.IsNullOrEmpty(secret))
            {
                return CustomEncode.StringToByte(secret, CustomEncode.UTF_8);
            }

            byte[] key = new byte[32];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            return key;
        }

        #endregion

        #region 台帳の鍵（#311 の段階 3）

        /// <summary>台帳に記録する、証明の指紋（#311 の段階 3）</summary>
        /// <param name="jkt">鍵の指紋（RFC 7638）</param>
        /// <param name="jti">証明の `jti`</param>
        /// <returns>記録に使う値（作れなければ空）</returns>
        /// <remarks>
        /// **`jti` だけを鍵にしない** — **`jti` の値はクライアントが決める**ので、
        /// **先に使われた値は、他の相手が使えなくなる**（**互いを塞げてしまう**）。
        /// **`jkt` と組にすれば、台帳は「鍵ごと」になる**（RFC 9449 §11.1）。
        ///
        /// **組にしてから指紋にする**のは、**`jti` の長さに上限が無い**ためと、
        /// **`jkt` をそのまま持たない**ため（**鍵の指紋は、そのクライアントを辿れる値**である）。
        ///
        /// **区切りに `.` を入れる** — **入れないと、
        /// 境目の違う 2 つの組が同じ値になりうる**（**それだけで別の相手を塞げる**）。
        ///
        /// **UTF-8 で読む**（**`ath` の us_ascii とは違う**）。
        /// **`jti` は相手が決める文字列**で、**ASCII の外の文字が入りうる** —
        /// **us_ascii で読むと、違う `jti` が同じ値に潰れて、通るはずの証明を断ってしまう。**
        /// </remarks>
        public static string ProofId(string jkt, string jti)
        {
            if (string.IsNullOrEmpty(jkt) || string.IsNullOrEmpty(jti))
            {
                return "";
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                return CustomEncode.ToBase64UrlString(sha256.ComputeHash(
                    CustomEncode.StringToByte(jkt + "." + jti, CustomEncode.UTF_8)));
            }
        }

        #endregion

        #region public

        /// <summary>DPoP の証明を検証し、鍵の指紋（`jkt`）を返す（#311 の段階 1）</summary>
        /// <param name="proof">`DPoP` ヘッダの値（証明の JWT）</param>
        /// <param name="htm">期待する HTTP メソッド（`POST` など。**大文字**）</param>
        /// <param name="htu">期待する宛先（クエリと素片を含まない URL）</param>
        /// <param name="noncePurpose">nonce の用途（`PurposeAs` / `PurposeRs`。**見ないなら null**）</param>
        /// <param name="jkt">out : 公開鍵の指紋（RFC 7638）</param>
        /// <param name="error">out : error（`invalid_dpop_proof`、または `use_dpop_nonce`）</param>
        /// <param name="errDescription">out : 断る理由（**そのまま応答に載せられる文**）</param>
        /// <returns>使ってよければ true</returns>
        /// <remarks>
        /// **見るもの**（RFC 9449 §4.3）。
        ///
        /// | | |
        /// |---|---|
        /// | **形** | **JWS（3 つの部分）であること** |
        /// | **`typ`** | **`dpop+jwt`**（**署名の検証と同時に確かめる**） |
        /// | **`alg`** | **この製品が扱う非対称の alg**（`SigningKeys` の表。**`none` は入っていない**） |
        /// | **`jwk`** | **在ること。** **公開鍵だけであること**（**秘密鍵の項目が無い**）。**`alg` と鍵の種類が合っていること** |
        /// | **署名** | **その `jwk` で検証できること** |
        /// | **`jti`** | **在ること**（**使い回しの検出は段階 3**） |
        /// | **`htm` / `htu`** | **期待どおりであること** |
        /// | **`iat`** | **窓の中であること** |
        /// | **`nonce`** | **`noncePurpose` が在り、要求する配備のときだけ見る**（段階 4） |
        /// | **使い回し** | **記録できたら初回**（段階 3。`DPoPProofProvider`） |
        ///
        /// **読めない値でも例外にしない**（外から来る値である。#241 と同じ扱い）。
        /// **断った理由はログに残す**（**値そのものは出さない**）。
        /// </remarks>
        public static bool Verify(
            string proof, string htm, string htu, string noncePurpose,
            out string jkt, out string error, out string errDescription)
        {
            jkt = "";
            error = CmnDPoP.InvalidDPoPProof;
            errDescription = "";

            try
            {
                JObject header = CmnEndpoints.TryReadJwtHeader(proof);
                JObject payload = CmnEndpoints.TryReadJwtPayload(proof);

                if (header == null || payload == null)
                {
                    errDescription = "The DPoP proof is not a JWS.";
                    return CmnDPoP.Deny(errDescription);
                }

                // typ（**署名の検証でも確かめるが、先に読んで分かる誤りは分けて返す**）
                if ((string)header[CmnDPoP.TypHeader] != CmnDPoP.Typ)
                {
                    errDescription = "The DPoP proof must have typ=" + CmnDPoP.Typ + ".";
                    return CmnDPoP.Deny(errDescription);
                }

                // alg（**自分が扱う非対称の alg だけ**。`SigningKeys` の表が持つ）
                string alg = (string)header[JwtConst.alg];

                if (!CmnAccessToken.IsSupportedAlg(alg))
                {
                    errDescription = "The DPoP proof is signed with an unsupported alg.";
                    return CmnDPoP.Deny(errDescription);
                }

                // jwk（**公開鍵だけ**。**alg と鍵の種類が合っていること**）
                JObject jwk = (JObject)header[CmnDPoP.JwkHeader];

                if (jwk == null)
                {
                    errDescription = "The DPoP proof must have a jwk header.";
                    return CmnDPoP.Deny(errDescription);
                }

                if (!CmnDPoP.IsPublicJwk(jwk))
                {
                    errDescription = "The jwk of the DPoP proof must not contain a private key.";
                    return CmnDPoP.Deny(errDescription);
                }

                if (!CmnAccessToken.IsSameKeyType(jwk, alg))
                {
                    errDescription = "The jwk of the DPoP proof does not match the alg.";
                    return CmnDPoP.Deny(errDescription);
                }

                // 署名（**その jwk で検証する**。**鍵は要求の中に在る**）
                SigningKeys.Entry key = SigningKeys.Of(alg);
                JWS jws = (key == null) ? null : key.CreateJwsFromJwk(jwk);

                if (jws == null || !jws.Verify(proof, CmnDPoP.Typ))
                {
                    errDescription = "The signature of the DPoP proof is invalid.";
                    return CmnDPoP.Deny(errDescription);
                }

                // jti（**在ること**。**使い回しの検出は、この後の記録で行う**）
                string jti = (string)payload[OAuth2AndOIDCConst.jti];

                if (string.IsNullOrEmpty(jti))
                {
                    errDescription = "The DPoP proof must have a jti.";
                    return CmnDPoP.Deny(errDescription);
                }

                // htm / htu
                if (!string.Equals((string)payload[CmnDPoP.Htm], htm, StringComparison.Ordinal))
                {
                    errDescription = "The htm of the DPoP proof does not match the request.";
                    return CmnDPoP.Deny(errDescription);
                }

                if (!CmnDPoP.IsSameUri((string)payload[CmnDPoP.Htu], htu))
                {
                    errDescription = "The htu of the DPoP proof does not match the request.";
                    return CmnDPoP.Deny(errDescription);
                }

                // iat（**窓の中**）
                if (!CmnDPoP.IsFreshIat(payload[OAuth2AndOIDCConst.iat]))
                {
                    errDescription = "The iat of the DPoP proof is not acceptable.";
                    return CmnDPoP.Deny(errDescription);
                }

                //  **nonce を要求する配備では、サーバが出した値であること**（RFC 9449 §8。段階 4）。
                //    **台帳に記録する前に見る** — **nonce を貰い直すための断りで、
                //    `jti` を焼いてしまわない**（**出し直す証明は、新しい `jti` で作られる**）。
                if (!CmnDPoP.CheckNonce(payload, noncePurpose, out errDescription))
                {
                    error = CmnDPoP.UseDPoPNonce;
                    return false;
                }

                jkt = CmnDPoP.Thumbprint(jwk);

                if (string.IsNullOrEmpty(jkt))
                {
                    errDescription = "The jwk of the DPoP proof could not be read.";
                    return CmnDPoP.Deny(errDescription);
                }

                //  **一度使った証明は、二度と通さない**（RFC 9449 §11.1。#311 の段階 3）。
                //    **ここが最後**であることに意味が在る —
                //    **検証に通らなかった証明で、`jti` を焼かせない**
                //    （**署名を壊した証明を投げるだけで、相手の `jti` を使えなくできてしまう**）。
                if (!DPoPProofProvider.TryRecord(CmnDPoP.ProofId(jkt, jti)))
                {
                    errDescription = "The DPoP proof has already been used.";
                    return CmnDPoP.Deny(errDescription);
                }

                return true;
            }
            catch (Exception ex)
            {
                // **外から来る値**なので、例外にしない（#241 と同じ扱い）。
                errDescription = "The DPoP proof could not be verified.";

                Logging.MyOperationTrace(string.Format(
                    "The DPoP proof could not be verified. ({0})", ex.GetType().Name));

                return false;
            }
        }

        /// <summary>JWK の指紋（RFC 7638。`jkt` の値）</summary>
        /// <param name="jwk">公開鍵の JWK</param>
        /// <returns>BASE64URL(SHA-256(正規化した JSON))。作れなければ空</returns>
        /// <remarks>
        /// **RFC 7638 : 必須の項目だけを、辞書順の JSON にして SHA-256 する。**
        /// **空白も改行も入れない。** **項目の順も決まっている。**
        ///
        /// | 鍵の種類 | 正規化する項目 |
        /// |---|---|
        /// | `RSA` | `e` / `kty` / `n` |
        /// | `EC` | `crv` / `kty` / `x` / `y` |
        ///
        /// **自分の鍵の `kid` も、同じ計算でできている**（`SigningKeys`。Open棟梁 の変換器が作る）。
        /// **ここで自分で組んでいるのは、相手の JWK をそのまま扱う口が無いため**である。
        /// </remarks>
        public static string Thumbprint(JObject jwk)
        {
            if (jwk == null)
            {
                return "";
            }

            string kty = (string)jwk[JwtConst.kty];
            string canonical = null;

            if (kty == JwtConst.RSA)
            {
                string e = (string)jwk[JwtConst.e];
                string n = (string)jwk[JwtConst.n];

                if (string.IsNullOrEmpty(e) || string.IsNullOrEmpty(n))
                {
                    return "";
                }

                canonical = "{\"e\":" + JsonConvert.ToString(e)
                    + ",\"kty\":" + JsonConvert.ToString(kty)
                    + ",\"n\":" + JsonConvert.ToString(n) + "}";
            }
            else if (kty == JwtConst.EC)
            {
                string crv = (string)jwk[JwtConst.crv];
                string x = (string)jwk[JwtConst.x];
                string y = (string)jwk[JwtConst.y];

                if (string.IsNullOrEmpty(crv)
                    || string.IsNullOrEmpty(x) || string.IsNullOrEmpty(y))
                {
                    return "";
                }

                canonical = "{\"crv\":" + JsonConvert.ToString(crv)
                    + ",\"kty\":" + JsonConvert.ToString(kty)
                    + ",\"x\":" + JsonConvert.ToString(x)
                    + ",\"y\":" + JsonConvert.ToString(y) + "}";
            }
            else
            {
                // **扱わない鍵の種類**（`oct` など。DPoP は非対称鍵である）。
                return "";
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                return CustomEncode.ToBase64UrlString(
                    sha256.ComputeHash(CustomEncode.StringToByte(canonical, CustomEncode.UTF_8)));
            }
        }

        #endregion

        #region private

        /// <summary>秘密鍵の項目が混ざっていないか</summary>
        /// <param name="jwk">JWK</param>
        /// <returns>公開鍵だけなら true</returns>
        private static bool IsPublicJwk(JObject jwk)
        {
            foreach (string member in CmnDPoP.PrivateMembers)
            {
                if (jwk[member] != null)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>`htu` が期待どおりか</summary>
        /// <param name="actual">証明の `htu`</param>
        /// <param name="expected">期待する宛先</param>
        /// <returns>同じなら true</returns>
        /// <remarks>
        /// **RFC 9449 §4.3 : クエリと素片を除いた URL を比べる。**
        ///
        /// **大文字小文字は区別しない。**
        /// **スキームとホストは RFC 3986 でも区別しない**し、
        /// **この製品が動く IIS / Kestrel は、パスでも区別しない** —
        /// **区別して弾くと、サーバが実際に受けた要求を「違う」と言うことになる。**
        ///
        /// **末尾の `/` は落として比べる**（**同じ口を指す書き方の違い**）。
        /// </remarks>
        private static bool IsSameUri(string actual, string expected)
        {
            if (string.IsNullOrEmpty(actual) || string.IsNullOrEmpty(expected))
            {
                return false;
            }

            if (!Uri.TryCreate(actual, UriKind.Absolute, out Uri a)
                || !Uri.TryCreate(expected, UriKind.Absolute, out Uri b))
            {
                return false;
            }

            return string.Equals(
                CmnDPoP.WithoutQuery(a), CmnDPoP.WithoutQuery(b),
                StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>クエリと素片を除いた URL（末尾の `/` も落とす）</summary>
        /// <param name="uri">URL</param>
        /// <returns>比べるための文字列</returns>
        private static string WithoutQuery(Uri uri)
        {
            return uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        }

        /// <summary>`iat` が窓の中か</summary>
        /// <param name="iat">`iat`（NumericDate）</param>
        /// <returns>窓の中なら true</returns>
        /// <remarks>**数値でなければ受けない**（文字列の `iat` は RFC 7519 §2 に反する）。</remarks>
        private static bool IsFreshIat(JToken iat)
        {
            if (iat == null || iat.Type != JTokenType.Integer)
            {
                return false;
            }

            DateTimeOffset issued = DateTimeOffset.FromUnixTimeSeconds((long)iat);
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (issued < now - CmnDPoP.PastWindow)
            {
                return false;
            }

            return issued <= now + CmnDPoP.FutureWindow;
        }

        /// <summary>断ったことをログに残す（**値は出さない**）</summary>
        /// <param name="reason">理由</param>
        /// <returns>false（そのまま返せるように）</returns>
        /// <remarks>
        /// **証明そのものも `jkt` も出さない**（**鍵の指紋は、そのクライアントを辿れる値**である）。
        /// **理由だけ**を残す。
        /// </remarks>
        private static bool Deny(string reason)
        {
            Logging.MyOperationTrace("The DPoP proof was denied. (" + reason + ")");

            return false;
        }

        #endregion
    }
}
