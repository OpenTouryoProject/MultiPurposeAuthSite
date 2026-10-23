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
//*  2026/10/22  玄人 幸道         証明の検証を Open棟梁 の DPoPProof に移した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Log;

using System;
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;

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
    ///
    /// **証明そのものの検証（形・`typ`・`alg`・`jwk`・署名・`jti`・`htm`・`htu`・`iat`）は、
    /// Open棟梁 の `DPoPProof` が行う**（#294）。
    /// **ここに残るのは配備の決め** — **`htu` の期待値の作り方・`nonce`・`jti` の台帳**である。
    /// </remarks>
    public class CmnDPoP
    {
        #region 定数

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
        /// **窓は `DPoPProof` の既定**（**検証に使う窓と同じもの**）。
        /// **台帳の側に長さを書かない** — **片方だけ直して食い違うのを防ぐ。**
        /// </remarks>
        public static readonly TimeSpan ProofReplayWindow =
            DPoPProof.DefaultPastWindow + DPoPProof.DefaultFutureWindow;

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

        #region nonce（#311 の段階 4）

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

            string nonce = (payload == null) ? null : (string)payload[OAuth2AndOIDCConst.nonce];

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
        /// **証明の検証は `DPoPProof.Verify`**（RFC 9449 §4.3。#294）。**この製品が足すもの**は次の 2 つ。
        ///
        /// | | |
        /// |---|---|
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
            error = OAuth2AndOIDCConst.invalid_dpop_proof;

            if (!DPoPProof.Verify(proof, htm, htu, out jkt, out JObject payload, out errDescription))
            {
                return CmnDPoP.Deny(errDescription);
            }

            if (!CmnDPoP.CheckNonceAndRecord(payload, jkt, noncePurpose, ref error, out errDescription))
            {
                jkt = "";
                return false;
            }

            return true;
        }

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
        /// **照合（`ath` ・ 証明の鍵と `cnf.jkt` の一致）は `DPoPProof.VerifyForResource`**（RFC 9449 §7.1。#294）。
        /// **`nonce` と使い回しは、照合に通った後で見る**（**通らない証明で `jti` を焼かせない**）。
        ///
        /// **`error` を返すのは、`use_dpop_nonce` を区別するため**である（§9。#311 の段階 4）。
        /// **それ以外は `invalid_token`**（**この口の従来の断り方** — **証明の中身は、要求元に教えない**）。
        /// </remarks>
        public static bool VerifyForResource(
            string proof, string htm, string htu,
            string accessToken, string boundJkt, out string error, out string errDescription)
        {
            error = OAuth2AndOIDCConst.invalid_token;

            if (!DPoPProof.VerifyForResource(
                proof, htm, htu, accessToken, boundJkt, out JObject payload, out errDescription))
            {
                return CmnDPoP.Deny(errDescription);
            }

            return CmnDPoP.CheckNonceAndRecord(
                payload, boundJkt, CmnDPoP.PurposeRs, ref error, out errDescription);
        }

        #endregion

        #region private

        /// <summary>検証に通った証明の `nonce` を見て、台帳に記録する</summary>
        /// <param name="payload">証明のペイロード</param>
        /// <param name="jkt">証明の鍵の指紋</param>
        /// <param name="noncePurpose">nonce の用途（見ないなら null）</param>
        /// <param name="error">ref : error（nonce で断るときだけ `use_dpop_nonce` にする）</param>
        /// <param name="errDescription">out : 断る理由</param>
        /// <returns>使ってよければ true</returns>
        private static bool CheckNonceAndRecord(
            JObject payload, string jkt, string noncePurpose, ref string error, out string errDescription)
        {
            //  **nonce を要求する配備では、サーバが出した値であること**（RFC 9449 §8。段階 4）。
            //    **台帳に記録する前に見る** — **nonce を貰い直すための断りで、
            //    `jti` を焼いてしまわない**（**出し直す証明は、新しい `jti` で作られる**）。
            if (!CmnDPoP.CheckNonce(payload, noncePurpose, out errDescription))
            {
                error = OAuth2AndOIDCConst.use_dpop_nonce;
                return false;
            }

            //  **一度使った証明は、二度と通さない**（RFC 9449 §11.1。#311 の段階 3）。
            //    **ここが最後**であることに意味が在る —
            //    **検証に通らなかった証明で、`jti` を焼かせない**
            //    （**署名を壊した証明を投げるだけで、相手の `jti` を使えなくできてしまう**）。
            if (!DPoPProofProvider.TryRecord(
                DPoPProof.CreateProofId(jkt, (string)payload[OAuth2AndOIDCConst.jti])))
            {
                errDescription = "The DPoP proof has already been used.";
                return CmnDPoP.Deny(errDescription);
            }

            return true;
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
