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
//* クラス名        ：SoftwareStatementProvider
//* クラス日本語名  ：software_statement の検証と、主張の重ね方（RFC 7591 2.3 / 3.1.1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/20  玄人 幸道         新規（#307 の段階 4）
//*  2026/10/22  玄人 幸道         汎用部品を Open棟梁 の実装に置き換えた（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.TokenProviders;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// `software_statement`（RFC 7591 §2.3 / §3.1.1）を検証し、主張を本文へ重ねる。
    /// </summary>
    /// <remarks>
    /// **`software_statement` は「署名付きの添え状」**である。
    /// **動的登録の本文（署名の無い JSON）に対して、
    /// 信頼する発行者が「この内容で登録してよい」と保証する。**
    ///
    /// **3 つの専用の資格情報とは、役が違う**（#307）。
    ///
    /// | | 何を証明するか | 段階 |
    /// |---|---|---|
    /// | `client_registration` scope の AT | **新しい登録を作ってよい人か**（認可） | 段階 1 |
    /// | `registration_access_token` | **その 1 件を直してよいか**（認可） | 段階 2 |
    /// | **`software_statement`** | **書かれている内容を信じてよいか**（**内容の保証**） | **段階 4** |
    /// | `token_endpoint_auth_method` | **認証のときに本人か** | 段階 3 |
    ///
    /// **statement は、どちらの AT も置き換えない**（段階 4 の決定）。
    /// **statement はソフトウェアに同梱されて配布される ＝ 秘密ではない**ので、
    /// **認可の代わりに使うと、誰でも登録できる口になる。**
    /// **RFC 7591 §1.2 の「AT を要らない開いた登録口」は、この配備では採らない。**
    ///
    /// **判定の順**（**認可が先、内容は後**。`ClientRegistrationProvider.Register`）。
    ///
    /// ```
    /// 404 → 401（AT）→ 403（scope / 2 件目）→ 400（メタデータ。ここで statement を見る）→ 201
    /// ```
    ///
    /// **認可されていない相手に、自分の statement が信頼されているかを知らせない。**
    /// **信頼一覧の中身を、外から探らせないため**である。
    /// </remarks>
    public static class SoftwareStatementProvider
    {
        #region 結果

        /// <summary>検証の結果</summary>
        /// <remarks>
        /// **誤りのコードへの対応は、呼ぶ側（`ClientRegistrationProvider`）が決める** —
        /// **RFC 7591 §3.2.2 のコードは、あの口でしか使わない。**
        /// </remarks>
        public enum Result
        {
            /// <summary>添えられていない</summary>
            None,

            /// <summary>検証できた（主張を重ねた）</summary>
            Verified,

            /// <summary>壊れている（`invalid_software_statement`）</summary>
            Invalid,

            /// <summary>信頼していない（`unapproved_software_statement`）</summary>
            Unapproved
        }

        #endregion

        #region メタデータとして扱わないクレーム

        /// <summary>JWT のクレーム（メタデータではない）</summary>
        /// <remarks>
        /// **RFC 7519 §4.1 の登録済みクレーム**である。
        /// **検証にだけ使い、メタデータとしては重ねない。**
        /// **これ以外は、すべてメタデータとして扱う**（RFC 7591 §2.3）。
        /// </remarks>
        private static readonly string[] JwtClaims = new string[]
        {
            OAuth2AndOIDCConst.iss,
            OAuth2AndOIDCConst.aud,
            OAuth2AndOIDCConst.exp,
            OAuth2AndOIDCConst.nbf,
            OAuth2AndOIDCConst.iat,
            OAuth2AndOIDCConst.jti,
            SoftwareStatementProvider.SoftwareStatement
        };

        /// <summary>メタデータの名前（RFC 7591 §2.3）</summary>
        public const string SoftwareStatement = "software_statement";

        #endregion

        #region 検証して重ねる

        /// <summary>
        /// `software_statement` を検証し、主張されたメタデータを本文へ重ねる。
        /// </summary>
        /// <param name="metadata">
        /// 要求の本文（**この場で書き換える**。`software_statement` は外し、
        /// 主張された項目で上書きする）
        /// </param>
        /// <param name="description">誤りの説明（通ったときは空）</param>
        /// <returns>結果</returns>
        /// <remarks>
        /// **順に見る**（**既存の配備の振る舞いを変えないため、1 番目が先**）。
        ///
        /// | 順 | 見るもの | 結果 |
        /// |---|---|---|
        /// | 1 | **信頼する発行者が 0 件** | **`Unapproved`**（**従来どおり断る**） |
        /// | 2 | JWT として読めない・署名の部分が無い | `Invalid` |
        /// | 3 | **`iss` が無い**（§2.3 は必須） | `Invalid` |
        /// | 4 | **`iss` が信頼一覧に無い** | **`Unapproved`** |
        /// | 5 | ヘッダの `alg` が、登録された alg と違う | `Invalid` |
        /// | 6 | **署名が合わない** | `Invalid` |
        /// | 7 | **`exp` が切れている**（在るときだけ見る） | `Invalid` |
        /// | 8 | **`aud` が自分でない**（在るときだけ見る） | `Invalid` |
        ///
        /// **`iat` / `nbf` は見ない**（段階 4 の決定）。
        ///
        /// **重ね方**（RFC 7591 §2.3 は **MUST**）。
        ///
        /// | | |
        /// |---|---|
        /// | **両方に在る項目** | **statement が勝つ**（**断らない。黙って上書きし、ログに残す**） |
        /// | statement だけに在る項目 | そのまま使う |
        /// | 本文だけに在る項目 | そのまま使う |
        /// | JWT のクレーム | **メタデータとして扱わない** |
        ///
        /// **`software_statement` 自身は、本文から外す**（§3.1.1 : メタデータとして保存しない）。
        /// **列にも応答にも出ない**（段階 4 の決定。**保管しないので、列を足していない**）。
        /// </remarks>
        public static Result Apply(JObject metadata, out string description)
        {
            description = "";

            if (metadata == null)
            {
                return Result.None;
            }

            JToken token = metadata[SoftwareStatementProvider.SoftwareStatement];

            if (token == null || token.Type == JTokenType.Null)
            {
                return Result.None;
            }

            //  **本文からは外す**（§3.1.1）。**この後どの道を通っても、保存する形には入らない。**
            metadata.Remove(SoftwareStatementProvider.SoftwareStatement);

            //  1. **信頼する発行者が 1 件も無い配備**（＝ 段階 4 の設定を書いていない配備）。
            //     **従来どおり断る。** **既定の配備の振る舞いを変えない**ためである。
            if (!SoftwareStatementIssuers.Any())
            {
                description = "This deployment does not accept a software_statement.";
                return Result.Unapproved;
            }

            //  2. **JWT として読めるか**（**外から来た値なので、例外にしない**。#241 と同じ作法）。
            string statement = (token.Type == JTokenType.String) ? (string)token : "";
            string[] segments = (statement ?? "").Split('.');

            JObject claims = JwtReader.TryReadPayload(statement);

            if (claims == null || segments.Length != 3 || string.IsNullOrEmpty(segments[2]))
            {
                description = "The software_statement is not a signed JWT.";
                return Result.Invalid;
            }

            //  3. **`iss` は必須**（RFC 7591 §2.3）。
            JToken issToken = claims[OAuth2AndOIDCConst.iss];
            string iss = (issToken != null && issToken.Type == JTokenType.String)
                ? (string)issToken : "";

            if (string.IsNullOrEmpty(iss))
            {
                description = "The software_statement must contain an iss claim.";
                return Result.Invalid;
            }

            //  4. **信頼している発行者か**（§3.2.2 の "not approved for use by this
            //     authorization server" に当たる）。
            SoftwareStatementIssuer issuer = SoftwareStatementIssuers.Find(iss);

            if (issuer == null)
            {
                description = "The issuer of the software_statement is not approved "
                    + "by this deployment.";
                return Result.Unapproved;
            }

            //  5. **ヘッダの `alg` を照合する**（**外から alg を選ばせない**。#262 と同じ方針）。
            string alg = JwtReader.TryReadAlg(statement);

            if (alg != issuer.Alg)
            {
                description = "The software_statement is not signed with the registered alg.";
                return Result.Invalid;
            }

            //  6. **署名の検証。**
            //     **`JWS.Verify(jwt)` は `typ` を照合しない版**である（上流 #611）。
            //     **`software_statement` の `typ` は仕様で決まっていない**ので、照合しない。
            //
            //  **鍵は n 本持てる**（#307 の段階 6）。**書いた順に試し、最初に通った鍵で通す。**
            //    **発行者が鍵を入れ替える間、新旧のどちらで署名された statement も通る**ためである。
            //
            //  **本文（DB の列）を先に、次にファイル（パス）**（#308 の段階 1）。
            //    **両方書いてよい** — **入れ替えの途中で、片方だけ本文に移せる。**
            int readable = 0;
            int verifiedAt = -1;
            int candidates = issuer.CerBodies.Count + issuer.CerFilePaths.Count;

            for (int i = 0; i < candidates; i++)
            {
                JWS jws = null;
                bool isBody = (i < issuer.CerBodies.Count);

                try
                {
                    jws = isBody
                        ? SoftwareStatementProvider.JwsFromCerBody(
                            issuer.Alg, issuer.CerBodies[i])
                        : JwsFactory.CreateFromCertificate(
                            issuer.Alg, issuer.CerFilePaths[i - issuer.CerBodies.Count]);
                }
                catch (Exception ex)
                {
                    //  **設定の誤り**（証明書が無い・読めない・本文が壊れている）。
                    //    **理由を残す**（#253 の方針）。**statement が壊れている訳ではない。**
                    //    **他の鍵が在れば、そちらを試す**（**1 本の誤りで全部を止めない**）。
                    Logging.MyOperationTrace(string.Format(
                        "The certificate ({0}, {1}) of the software_statement issuer {2} "
                        + "could not be read. ({3})",
                        i + 1, isBody ? "body" : "file", issuer.Label, ex.GetType().Name));

                    continue;
                }

                if (jws == null)
                {
                    //  **alg の表に無い**（`IsUsable` で弾いているので、ここには来ない）。
                    continue;
                }

                readable++;

                try
                {
                    if (jws.Verify(statement))
                    {
                        verifiedAt = i;
                        break;
                    }
                }
                catch
                {
                    //  **壊れた値で例外にしない**（外から来た値である）。
                }
            }

            if (readable == 0)
            {
                //  **1 本も読めなかった** ＝ **検証する材料が無い。**
                //    **「信頼していない」に倒す**（**statement が壊れている訳ではない**）。
                description = "The issuer of the software_statement is not approved "
                    + "by this deployment.";
                return Result.Unapproved;
            }

            if (verifiedAt < 0)
            {
                description = "The signature of the software_statement is not verified.";
                return Result.Invalid;
            }

            if (0 < verifiedAt)
            {
                // オペレーション・トレース・ログ出力
                //   **1 本目以外で通った** ＝ **鍵の入れ替えが進んでいる印**である。
                //   **運用者が「古い鍵をいつ消せるか」を判断する材料**になる。
                Logging.MyOperationTrace(string.Format(
                    "The software_statement of the issuer {0} was verified "
                    + "with the certificate ({1} of {2}).",
                    issuer.Label, verifiedAt + 1, candidates));
            }

            //  7. **`exp`（在るときだけ）。** **RFC 7591 §2.3 では任意**だが、
            //     **在るなら効かせる** — **切れた保証を使わせない。**
            if (!SoftwareStatementProvider.IsAlive(claims))
            {
                description = "The software_statement has expired.";
                return Result.Invalid;
            }

            //  8. **`aud`（在るときだけ）。** **仕様は定めていない**が、
            //     **他の認可サーバ向けの statement を、ここで使い回させない。**
            //     **期待値は `IssuerId`**（この認可サーバの名前）。
            JToken audToken = claims[OAuth2AndOIDCConst.aud];

            if (audToken != null && audToken.Type != JTokenType.Null
                && !IdTokenAudience.Matches(claims, CmnServerParams.IssuerId))
            {
                description = "The software_statement was not issued for this "
                    + "authorization server.";
                return Result.Invalid;
            }

            //  9. **この発行者に許した範囲に収まっているか**（#307 の段階 6）。
            //
            //  **重ねる前に見る** — **重ねてから断ると、
            //    「受け入れた」ログを出した後で断る**ことになり、記録が食い違う。
            //
            //  **見るのは「重ねた後の値」**である（statement 由来でも、本文由来でも）。
            //    **その発行者の保証で作られる登録、全体の上限**だからである。
            if (!SoftwareStatementProvider.IsWithinAllowed(
                metadata, claims, issuer, out string exceeded))
            {
                description = "The software_statement claims " + exceeded
                    + " that is not allowed for this issuer.";
                return Result.Unapproved;
            }

            //  **主張を重ねる**（§2.3 は MUST）。
            SoftwareStatementProvider.Merge(metadata, claims, issuer, iss);

            return Result.Verified;
        }

        #endregion

        #region Private

        /// <summary>`exp` が切れていないか（無ければ切れていない扱い）</summary>
        /// <param name="claims">statement のクレーム</param>
        /// <returns>使えるなら true</returns>
        private static bool IsAlive(JObject claims)
        {
            JToken exp = claims[OAuth2AndOIDCConst.exp];

            if (exp == null || exp.Type == JTokenType.Null)
            {
                //  **`exp` は任意**（RFC 7591 §2.3）。**無ければ期限なし。**
                return true;
            }

            long expires = 0;

            if (!long.TryParse(exp.ToString(), out expires))
            {
                //  **数でない `exp`** ＝ 壊れている。
                return false;
            }

            return DateTimeOffset.UtcNow.ToUnixTimeSeconds() < expires;
        }

        /// <summary>証明書の本文から、検証する JWS を作る（#308 の段階 1）</summary>
        /// <param name="alg">alg</param>
        /// <param name="base64">証明書（Base64 の DER）</param>
        /// <returns>JWS（alg が表に無ければ null）</returns>
        /// <remarks>
        /// **DB に本文で持った証明書で検証するため**に在る。
        ///
        /// **証明書を読むのは、ここ**である。
        /// **`SigningKeys` には置けない** — **あのファイルは `CreateJwkSetJson`（net48 の exe）
        /// からソース参照されており**、**`X509CertificateLoader` は net48 に無く、
        /// `new X509Certificate2(byte[])` は net10.0 で旧形式**（SYSLIB0057）である。
        /// **ターゲットで分ける書き方は、CommonLibrary 側でだけ使える**
        /// （`CmnSaml2Response.RsaFromCerFile` と同じ事情）。
        ///
        /// **`SigningKeys` が持つのは「パラメタ → JWS」の対応**だけにしてある
        /// （**alg → class の表を 2 つに増やさない**）。
        ///
        /// **読めない本文は例外になる**（呼ぶ側が受けて、次の鍵を試す）。
        /// </remarks>
        private static JWS JwsFromCerBody(string alg, string base64)
        {
            byte[] der = Convert.FromBase64String(base64);

            //  **証明書の読み込みはターゲットで分ける**（`CmnSaml2Response` と同じ）。
#if NETFX
            X509Certificate2 cert = new X509Certificate2(der);
#else
            X509Certificate2 cert = X509CertificateLoader.LoadCertificate(der);
#endif

            //  **破棄しない。** **公開鍵は証明書に紐づく**ので、
            //    **先に破棄すると、この後の検証で使えない**（`CmnSaml2Response` の注と同じ）。
            if (alg == JwtConst.ES256 || alg == JwtConst.ES384 || alg == JwtConst.ES512)
            {
                ECDsa ecdsa = cert.GetECDsaPublicKey();

                return (ecdsa == null) ? null
                    : JwsFactory.CreateFromEcParameters(alg, ecdsa.ExportParameters(false));
            }

            RSA rsa = cert.GetRSAPublicKey();

            return (rsa == null) ? null
                : JwsFactory.CreateFromRsaParameters(alg, rsa.ExportParameters(false));
        }

        /// <summary>発行者に許した範囲に収まっているか（#307 の段階 6）</summary>
        /// <param name="metadata">要求の本文</param>
        /// <param name="claims">statement のクレーム</param>
        /// <param name="issuer">発行者</param>
        /// <param name="exceeded">範囲外だった項目と値（断る理由に使う）</param>
        /// <returns>収まっていれば true</returns>
        /// <remarks>
        /// **上限は `allowed_scope` / `allowed_grant_types`**（**空なら絞らない**）。
        ///
        /// **見るのは「重ねた後の値」**である。
        /// **statement に書かれていなければ本文の値**が、その登録の値になるので、
        /// **本文由来の値も上限に収める**（**その発行者の保証で作られる登録、全体の上限**）。
        ///
        /// **値は理由に出す。** **断る相手は、登録を要求した側**であり、
        /// **自分が送った値（と statement の値）しか出ていない** —
        /// **配備の設定（上限そのもの）は出さない。**
        /// </remarks>
        private static bool IsWithinAllowed(
            JObject metadata, JObject claims,
            SoftwareStatementIssuer issuer, out string exceeded)
        {
            exceeded = "";

            if (!SoftwareStatementProvider.IsWithin(
                metadata, claims, "scope", issuer.AllowedScope, out string overScope))
            {
                exceeded = "a scope (" + overScope + ")";
                return false;
            }

            if (!SoftwareStatementProvider.IsWithin(
                metadata, claims, "grant_types", issuer.AllowedGrantTypes, out string overGrant))
            {
                exceeded = "a grant_type (" + overGrant + ")";
                return false;
            }

            return true;
        }

        /// <summary>その項目が、許した範囲に収まっているか（#307 の段階 6）</summary>
        /// <param name="metadata">要求の本文</param>
        /// <param name="claims">statement のクレーム</param>
        /// <param name="name">メタデータの名前（`scope` / `grant_types`）</param>
        /// <param name="allowed">許した範囲（空白区切り。空なら絞らない）</param>
        /// <param name="exceeded">範囲外だった最初の値</param>
        /// <returns>収まっていれば true</returns>
        /// <remarks>
        /// **`scope` は空白区切りの文字列、`grant_types` は配列**（RFC 7591 §2）だが、
        /// **どちらの形でも読めるようにしてある**（`ClientRegistrationProvider.GetStrings`
        /// と同じ寛さ。**外から来た値である**）。
        /// </remarks>
        private static bool IsWithin(
            JObject metadata, JObject claims, string name, string allowed, out string exceeded)
        {
            exceeded = "";

            if (string.IsNullOrWhiteSpace(allowed))
            {
                //  **書いていなければ絞らない**（段階 4 までと同じ振る舞い）。
                return true;
            }

            List<string> permitted = OAuth2AndOIDCSpec.ToDistinctList(allowed);

            //  **statement に在ればそれが登録の値**（§2.3 は MUST）。**無ければ本文の値。**
            JToken token = (claims[name] != null && claims[name].Type != JTokenType.Null)
                ? claims[name] : metadata[name];

            foreach (string value in SoftwareStatementProvider.Values(token))
            {
                if (!permitted.Contains(value))
                {
                    exceeded = value;
                    return false;
                }
            }

            return true;
        }

        /// <summary>メタデータの値を、文字列の列として読む（#307 の段階 6）</summary>
        /// <param name="token">値（配列 ／ 空白区切りの文字列 ／ 無し）</param>
        /// <returns>値の列（空のときは空の列）</returns>
        private static List<string> Values(JToken token)
        {
            List<string> ret = new List<string>();

            if (token == null || token.Type == JTokenType.Null)
            {
                return ret;
            }

            if (token.Type == JTokenType.Array)
            {
                foreach (JToken item in (JArray)token)
                {
                    string value = ((string)item ?? "").Trim();

                    if (!string.IsNullOrEmpty(value) && !ret.Contains(value))
                    {
                        ret.Add(value);
                    }
                }

                return ret;
            }

            return OAuth2AndOIDCSpec.ToDistinctList((string)token ?? "");
        }

        /// <summary>主張されたメタデータを、本文へ重ねる</summary>
        /// <param name="metadata">要求の本文（この場で書き換える）</param>
        /// <param name="claims">statement のクレーム</param>
        /// <param name="issuer">発行者</param>
        /// <param name="iss">`iss`</param>
        private static void Merge(
            JObject metadata, JObject claims, SoftwareStatementIssuer issuer, string iss)
        {
            List<string> overridden = new List<string>();

            foreach (JProperty claim in claims.Properties())
            {
                if (0 <= Array.IndexOf(SoftwareStatementProvider.JwtClaims, claim.Name))
                {
                    // **JWT のクレーム**（メタデータではない）。
                    continue;
                }

                JToken current = metadata[claim.Name];

                if (current != null && !JToken.DeepEquals(current, claim.Value))
                {
                    //  **本文と食い違った。** **statement が勝つ**（§2.3 は MUST）。
                    overridden.Add(claim.Name);
                }

                //  **複製して入れる**（**元の木に親を持たせ替えない**）。
                metadata[claim.Name] = claim.Value.DeepClone();
            }

            // オペレーション・トレース・ログ出力
            //   **誰の保証で登録されたかを残す。**
            //   **値は書かない**（**上書きされた項目の名前だけ**）。
            Logging.MyOperationTrace(string.Format(
                "The software_statement issued by {0} ({1}) was accepted. "
                + "(overridden: {2})",
                iss, issuer.Label,
                (overridden.Count == 0) ? "none" : string.Join(", ", overridden.ToArray())));
        }

        #endregion
    }
}
