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
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.TokenProviders;

using System;
using System.Collections.Generic;

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

            JObject claims = CmnEndpoints.TryReadJwtPayload(statement);

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
            string alg = CmnEndpoints.TryReadJwtAlg(statement);

            if (alg != issuer.Alg)
            {
                description = "The software_statement is not signed with the registered alg.";
                return Result.Invalid;
            }

            //  6. **署名の検証。**
            //     **`JWS.Verify(jwt)` は `typ` を照合しない版**である（上流 #611）。
            //     **`software_statement` の `typ` は仕様で決まっていない**ので、照合しない。
            JWS jws = null;

            try
            {
                jws = SigningKeys.CreateJwsFromCer(issuer.Alg, issuer.CerFilePath);
            }
            catch (Exception ex)
            {
                //  **設定の誤り**（証明書が無い・読めない）。**理由を残す**（#253 の方針）。
                //    **statement が壊れている訳ではない**ので、**「信頼していない」に倒す。**
                Logging.MyOperationTrace(string.Format(
                    "The certificate of the software_statement issuer {0} could not be read. ({1})",
                    issuer.Label, ex.GetType().Name));

                jws = null;
            }

            if (jws == null)
            {
                description = "The issuer of the software_statement is not approved "
                    + "by this deployment.";
                return Result.Unapproved;
            }

            bool verified = false;

            try
            {
                verified = jws.Verify(statement);
            }
            catch
            {
                //  **壊れた値で例外にしない**（外から来た値である）。
                verified = false;
            }

            if (!verified)
            {
                description = "The signature of the software_statement is not verified.";
                return Result.Invalid;
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
                && !IdTokenAudience.Matches(claims, Config.IssuerId))
            {
                description = "The software_statement was not issued for this "
                    + "authorization server.";
                return Result.Invalid;
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
