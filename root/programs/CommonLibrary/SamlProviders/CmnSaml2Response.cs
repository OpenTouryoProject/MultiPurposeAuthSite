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
//* クラス名        ：CmnSaml2Response
//* クラス日本語名  ：SAML2 の応答（SAMLResponse）の検証
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/10  玄人 幸道         新規（#286 の段階 1：鍵と期待Issuerを引数で受ける）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Str;

/// <summary>MultiPurposeAuthSite.SamlProviders</summary>
namespace MultiPurposeAuthSite.SamlProviders
{
    /// <summary>
    /// SAML2 の応答（SAMLResponse）を検証する（#286 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **`SAML2Client.VerifyResponse` を使わない。**
    /// **あちらは検証鍵を引数に取らず、`CmnClientParams.RsaCerFilePath`（＝ `SpRp_RsaCerFilePath`）
    /// の 1 本で検証する**ので、**相手ごとに鍵を替えられない。**
    ///
    /// **この配備では、その 1 本が自分の証明書である。**
    ///
    /// | | `SpRp_RsaCerFilePath` の役 |
    /// |---|---|
    /// | SAML | **`/samlmetadata` の `KeyDescriptor`**（自分の証明書を広告する） |
    /// | OIDC | **`JwkSet.json`（`/jwkcerts`）の素** |
    /// | 共通 | **検証の控え**（`kid` が引けないとき） |
    /// | クライアント役 | **相手の公開鍵**（`SAML2Client.VerifyResponse` が読む先） |
    ///
    /// **だから、上流 IdP の証明書に差し替えることができない**
    /// （Open棟梁 側の課題として起票してある）。
    ///
    /// **そこで、ここでは土台（`SAML2Bindings`）を直に呼ぶ。**
    /// **署名検証そのものは `SAML2Bindings.VerifyRedirect` / `VerifyPost`** であり、
    /// **要求（`AuthnRequest`）の検証と同じもの**である（`CmnEndpoints.VerifySamlRequest`）。
    /// **検証の実装が 2 本になるわけではない。**
    ///
    /// **この型は、`SAML2Client.VerifyResponse` の中身を写し、
    /// 鍵と期待 Issuer を引数にしたものである。** 判定の中身は変えていない。
    ///
    /// | 判定 | 根拠 |
    /// |---|---|
    /// | 署名と XML（スキーマ） | 従来から |
    /// | Issuer が**期待値**と一致 | **呼び出し側が渡す**（自己テストは自分、ID 連携は上流） |
    /// | Audience が自分の ACS URL | SAML Core 2.5.1.4 |
    /// | Recipient が自分の ACS URL | 同上 |
    /// | InResponseTo が、送った `AuthnRequest` の ID | Web SSO Profile 4.1.4.3 |
    /// | RelayState が、送った state | — |
    /// | `NotOnOrAfter` を過ぎていない | SAML Core 2.5.1.2 |
    /// | `StatusCode` が `Success` | SAML Core 3.2.2 |
    /// </remarks>
    public class CmnSaml2Response
    {
        #region 結果

        /// <summary>SAML2 の応答を検証した結果</summary>
        /// <remarks>
        /// **画面で目視するためのもの**（#246 の項目 3）。
        /// **アサーションの XML と、検証の結果と、読み取った属性**を持つ。
        ///
        /// **ID 連携（#286）も、同じ型を受け取る。**
        /// **そちらは画面に出さず、`Verdict` と `NameId` を使う。**
        /// </remarks>
        public class Saml2Result
        {
            /// <summary>判定（NORMAL_END / ABNORMAL_END）</summary>
            public string Verdict { get; set; }

            /// <summary>その判定になった理由</summary>
            public string Reason { get; set; }

            /// <summary>バインディング（どう受け取ったか）</summary>
            public string Binding { get; set; }

            /// <summary>SigAlg（Redirect Binding のときだけ付く）</summary>
            public string SigAlg { get; set; }

            /// <summary>RelayState</summary>
            public string RelayState { get; set; }

            /// <summary>RelayState が、送った state と一致したか（送っていなければ null）</summary>
            public bool? RelayStateMatched { get; set; }

            /// <summary>Audience が、自分の ACS URL と一致したか（#276。期待値が無ければ null）</summary>
            /// <remarks>SAML Core 2.5.1.4。**自分あてのアサーションか**を確かめる。</remarks>
            public bool? AudienceMatched { get; set; }

            /// <summary>Recipient が、自分の ACS URL と一致したか（#276。同上）</summary>
            public bool? RecipientMatched { get; set; }

            /// <summary>InResponseTo が、送った AuthnRequest の ID と一致したか（#276）</summary>
            public bool? InResponseToMatched { get; set; }

            /// <summary>NotOnOrAfter を過ぎていないか（#276。読めなければ null）</summary>
            public bool? NotExpired { get; set; }

            /// <summary>署名（と XML・値の整合）を検証できたか</summary>
            public bool SignatureVerified { get; set; }

            /// <summary>Issuer が、期待値と一致したか</summary>
            public bool IssuerMatched { get; set; }

            /// <summary>NameID（誰として認証されたか）</summary>
            public string NameId { get; set; }

            /// <summary>Issuer</summary>
            public string Issuer { get; set; }

            /// <summary>Audience</summary>
            public string Audience { get; set; }

            /// <summary>InResponseTo（要求の ID）</summary>
            public string InResponseTo { get; set; }

            /// <summary>Recipient（SubjectConfirmationData）</summary>
            public string Recipient { get; set; }

            /// <summary>NotOnOrAfter（これを過ぎたら使えない）</summary>
            public string NotOnOrAfter { get; set; }

            /// <summary>StatusCode</summary>
            public string StatusCode { get; set; }

            /// <summary>NameIDFormat</summary>
            public string NameIdFormat { get; set; }

            /// <summary>AuthnContextClassRef（どう認証したか）</summary>
            public string AuthnContextClassRef { get; set; }

            /// <summary>応答の XML（字下げして出す。空なら読めなかった）</summary>
            public string ResponseXml { get; set; }
        }

        #endregion

        #region 検証

        /// <summary>SAML2 の応答（SAMLResponse）を検証する</summary>
        /// <param name="samlResponse">SAMLResponse（受け取ったまま）</param>
        /// <param name="queryString">クエリ文字列（Redirect Binding のときだけ。署名の対象）</param>
        /// <param name="sigAlg">SigAlg（同上）</param>
        /// <param name="relayState">RelayState</param>
        /// <param name="expectedRelayState">送った state（照合する。無ければ空）</param>
        /// <param name="isGet">GET（Redirect Binding）で受け取ったか</param>
        /// <param name="expectedAcsUrl">
        /// 自分の ACS URL（#276）。**Audience と Recipient の両方に照合する**（空なら照合しない）。
        /// </param>
        /// <param name="expectedInResponseTo">送った AuthnRequest の ID（空なら照合しない）</param>
        /// <param name="cerFilePath">
        /// **署名を検証する証明書**（`.cer` のパス）。
        /// **自己テストは自分の `SpRp_RsaCerFilePath`、ID 連携は上流の証明書**を渡す。
        /// </param>
        /// <param name="expectedIssuer">
        /// **期待する Issuer**（EntityID）。
        /// **自己テストは自分の `Config.IssuerId`、ID 連携は上流の EntityID**を渡す。
        /// </param>
        /// <returns>結果</returns>
        /// <remarks>
        /// **`SAML2Client.VerifyResponse` は `bool` しか返さない**ので、
        /// **呼び出し側が理由を推定していた**（#276）。
        /// **ここでは中身を写してあるが、推定の形は変えていない**
        /// （**`SA-*` が画面の文言を測っている**ため。#278）。
        /// </remarks>
        public static Saml2Result Verify(
            string samlResponse, string queryString, string sigAlg,
            string relayState, string expectedRelayState, bool isGet,
            string expectedAcsUrl, string expectedInResponseTo,
            string cerFilePath, string expectedIssuer)
        {
            Saml2Result ret = new Saml2Result()
            {
                Verdict = "ABNORMAL_END",
                Reason = "",
                Binding = isGet ? "Redirect（GET。署名はクエリ文字列に付く）" : "POST（署名は XML の中）",
                SigAlg = sigAlg ?? "",
                RelayState = relayState ?? "",
                RelayStateMatched = string.IsNullOrEmpty(expectedRelayState)
                    ? (bool?)null : (relayState == expectedRelayState),
                SignatureVerified = false,
                IssuerMatched = false,
                AudienceMatched = null,
                RecipientMatched = null,
                InResponseToMatched = null,
                NotExpired = null,
                NameId = "",
                Issuer = "",
                Audience = "",
                InResponseTo = "",
                Recipient = "",
                NotOnOrAfter = "",
                StatusCode = "",
                NameIdFormat = "",
                AuthnContextClassRef = "",
                ResponseXml = ""
            };

            if (string.IsNullOrEmpty(samlResponse))
            {
                ret.Reason = "SAMLResponse が無い。";
                return ret;
            }

            // **Redirect Binding は RSAwithSHA1 だけを受ける**（従来どおり）。
            if (isGet && SAML2Const.RSAwithSHA1 != sigAlg)
            {
                ret.Reason = "SigAlg が RSAwithSHA1 ではないため、検証していない : "
                    + (string.IsNullOrEmpty(sigAlg) ? "（無し）" : sigAlg);
                return ret;
            }

            if (string.IsNullOrEmpty(cerFilePath))
            {
                // **鍵が無ければ検証できない。** **通してはならない。**
                ret.Reason = "署名を検証する証明書が設定されていない。";
                return ret;
            }

            XmlDocument samlResponse2 = null;
            XmlNamespaceManager samlNsMgr = null;
            SAML2Enum.StatusCode? statusCode = null;

            //  **展開したものを控える**（POST の署名検証でも使う。2 度展開しない）。
            string decodeSaml = "";

            #region 準備（読めるところまで読む）

            try
            {
                decodeSaml = isGet
                    ? SAML2Bindings.DecodeRedirect(queryString)
                    : SAML2Bindings.DecodePost(samlResponse);

                samlResponse2 = new XmlDocument();
                samlResponse2.PreserveWhitespace = false;
                samlResponse2.LoadXml(decodeSaml);

                samlNsMgr = SAML2Bindings.CreateNamespaceManager(samlResponse2);

                //  **StatusCode は、検証より前に読む**（Open棟梁 #598 と同じ理由）。
                //    **エラー応答（Assertion を持たない）でも理由を出せるようにする。**
                SAML2Enum.StringToEnum(
                    SAML2Bindings.GetStatusCodeInResponse(samlResponse2, samlNsMgr),
                    out statusCode);
            }
            catch (Exception ex)
            {
                // **応答が XML でない・署名の要素が無いなどで例外になっても、結果は返す。**
                ret.Reason = "応答を読めなかった : " + ex.GetType().Name;
                return ret;
            }

            ret.StatusCode = (statusCode == null) ? "" : statusCode.ToString();
            ret.ResponseXml = CmnSaml2Response.FormatXml(samlResponse2);

            #endregion

            #region 署名と XML（スキーマ）

            bool verified = false;

            try
            {
                //  **鍵は引数から**（ここが `SAML2Client.VerifyResponse` との違い）。
                DigitalSignX509 dsX509 = new DigitalSignX509(
                    cerFilePath, "", HashAlgorithmName.SHA256);

                if (isGet)
                {
                    // **Redirect Binding は、クエリ文字列そのものが署名の対象**である。
                    if (SAML2Bindings.VerifyRedirect(queryString, dsX509))
                    {
                        verified = SAML2Bindings.VerifyByXPath(
                            samlResponse2, SAML2Enum.SamlSchema.Response, samlNsMgr);
                    }
                }
                else
                {
                    // **POST Binding は、XML の中の署名**である。
                    string id = SAML2Bindings.GetIdInResponse(samlResponse2, samlNsMgr);

                    if (SAML2Bindings.VerifyPost(
                        decodeSaml, id, dsX509.X509Certificate.GetRSAPublicKey()))
                    {
                        verified = SAML2Bindings.VerifyByXPath(
                            samlResponse2, SAML2Enum.SamlSchema.Response, samlNsMgr);
                    }
                }
            }
            catch (Exception ex)
            {
                ret.Reason = "署名を検証できなかった : " + ex.GetType().Name;
                return ret;
            }

            #endregion

            #region 値（Assertion の中身）

            if (verified && statusCode == SAML2Enum.StatusCode.Success)
            {
                // **Issuer**（Response と Assertion の食い違いを見る）
                string iss = CmnSaml2Response.Pick(
                    SAML2Bindings.GetIssuerInResponse(samlResponse2, samlNsMgr),
                    SAML2Bindings.GetIssuerInAssertion(samlResponse2, samlNsMgr),
                    out bool issConflicted);

                // **NameID**
                string nameId = "";
                string format = "";
                SAML2Bindings.GetNameIDInAssertion(
                    samlResponse2, samlNsMgr, out format, out nameId);

                SAML2Enum.NameIDFormat? nameIDFormat = null;
                SAML2Enum.StringToEnum(format, out nameIDFormat);

                // **SubjectConfirmationData**（InResponseTo / NotOnOrAfter / Recipient）
                string inResponseTo1 = "";
                string notOnOrAfter1 = "";
                string recipient = "";
                SAML2Bindings.GetSubjectConfirmationDataInAssertion(
                    samlResponse2, samlNsMgr, out inResponseTo1, out notOnOrAfter1, out recipient);

                string inResponseTo = CmnSaml2Response.Pick(
                    inResponseTo1,
                    SAML2Bindings.GetInResponseToInResponse(samlResponse2, samlNsMgr),
                    out bool inResponseToConflicted);

                // **Conditions**
                string aud = SAML2Bindings.GetAudienceInAssertion(samlResponse2, samlNsMgr);

                //  **NotOnOrAfter は 2 か所にある**（SubjectConfirmationData と Conditions）。
                //    **短い方を採る**（Open棟梁 の `VerifyResponse` と同じ）。
                DateTime? notOnOrAfter = CmnSaml2Response.Earlier(
                    notOnOrAfter1,
                    SAML2Bindings.GetConditionsNotOnOrAfterInAssertion(samlResponse2, samlNsMgr));

                SAML2Enum.AuthnContextClassRef? authnContextClassRef = null;
                SAML2Enum.StringToEnum(
                    SAML2Bindings.GetAuthnContextClassRefInAssertion(samlResponse2, samlNsMgr),
                    out authnContextClassRef);

                ret.Issuer = iss ?? "";
                ret.NameId = nameId ?? "";
                ret.NameIdFormat = (nameIDFormat == null) ? "" : nameIDFormat.ToString();
                ret.InResponseTo = inResponseTo ?? "";
                ret.Recipient = recipient ?? "";
                ret.Audience = aud ?? "";
                ret.NotOnOrAfter = (notOnOrAfter == null)
                    ? "" : ((DateTime)notOnOrAfter).ToString("yyyy-MM-dd HH:mm:ss");
                ret.AuthnContextClassRef =
                    (authnContextClassRef == null) ? "" : authnContextClassRef.ToString();

                ret.NotExpired = (notOnOrAfter == null)
                    ? (bool?)null : (DateTime.UtcNow <= (DateTime)notOnOrAfter);

                //  **食い違い・期限切れは、ここで落とす**
                //    （Open棟梁 の `VerifyResponse` が `false` を返していたのと同じ条件）。
                if (issConflicted || inResponseToConflicted
                    || notOnOrAfter == null || ret.NotExpired == false)
                {
                    verified = false;
                }
            }
            else if (verified)
            {
                // **`Success` ではない。** **アサーションは使えない。**
                verified = false;
            }

            ret.SignatureVerified = verified;

            #endregion

            #region 照合（期待値との突き合わせ）

            ret.IssuerMatched = (ret.Issuer == expectedIssuer);

            if (!string.IsNullOrEmpty(expectedAcsUrl))
            {
                ret.AudienceMatched = (ret.Audience == expectedAcsUrl);
                ret.RecipientMatched = (ret.Recipient == expectedAcsUrl);
            }

            if (!string.IsNullOrEmpty(expectedInResponseTo))
            {
                ret.InResponseToMatched = (ret.InResponseTo == expectedInResponseTo);
            }

            #endregion

            #region 判定の理由

            if (!ret.SignatureVerified)
            {
                if (!string.IsNullOrEmpty(ret.StatusCode)
                    && statusCode != SAML2Enum.StatusCode.Success)
                {
                    ret.Reason = "エラー応答である（StatusCode=" + ret.StatusCode + "）。";
                }
                else if (ret.NotExpired == false)
                {
                    ret.Reason = "アサーションの有効期限が切れている（NotOnOrAfter="
                        + ret.NotOnOrAfter + "）。";
                }
                else
                {
                    ret.Reason = "署名または XML（スキーマ）の検証で落ちた。";
                }
            }
            else if (!ret.IssuerMatched)
            {
                ret.Reason = "Issuer が期待値と違う : "
                    + (string.IsNullOrEmpty(ret.Issuer) ? "（無し）" : ret.Issuer)
                    + "（期待 : " + expectedIssuer + "）";
            }
            else if (ret.AudienceMatched == false)
            {
                ret.Reason = "Audience が自分の ACS URL と違う : "
                    + (string.IsNullOrEmpty(ret.Audience) ? "（無し）" : ret.Audience)
                    + "（期待 : " + expectedAcsUrl + "）";
            }
            else if (ret.RecipientMatched == false)
            {
                ret.Reason = "Recipient が自分の ACS URL と違う : "
                    + (string.IsNullOrEmpty(ret.Recipient) ? "（無し）" : ret.Recipient)
                    + "（期待 : " + expectedAcsUrl + "）";
            }
            else if (ret.InResponseToMatched == false)
            {
                // **値そのものは出す**（ID は秘密ではないが、照合の証拠になる）。
                ret.Reason = "InResponseTo が、送った要求の ID と違う : "
                    + (string.IsNullOrEmpty(ret.InResponseTo) ? "（無し）" : ret.InResponseTo)
                    + "（期待 : " + expectedInResponseTo + "）";
            }
            else if (ret.RelayStateMatched == false)
            {
                ret.Reason = "RelayState が、送った state と違う。";
            }
            else
            {
                ret.Verdict = "NORMAL_END";
                ret.Reason = "署名、Issuer、Audience、Recipient、InResponseTo、RelayState を照合した。";
            }

            #endregion

            return ret;
        }

        #endregion

        #region private

        /// <summary>2 か所に書かれた同じ値を 1 つに決める</summary>
        /// <param name="value1">片方（Assertion 側）</param>
        /// <param name="value2">もう片方（Response 側）</param>
        /// <param name="conflicted">両方に値があって食い違っていたら true</param>
        /// <returns>採った値</returns>
        /// <remarks>
        /// **Open棟梁 の `VerifyResponse` と同じ決め方**である。
        /// **片方しか無ければそれを採り、食い違っていたら使えないものとして扱う。**
        /// </remarks>
        private static string Pick(string value1, string value2, out bool conflicted)
        {
            conflicted = false;

            if (value1 == value2)
            {
                return value1;
            }

            if (string.IsNullOrEmpty(value1))
            {
                return value2;
            }

            if (string.IsNullOrEmpty(value2))
            {
                return value1;
            }

            conflicted = true;

            return value1;
        }

        /// <summary>2 つの W3C タイムスタンプのうち、早い方を返す</summary>
        /// <param name="value1">片方</param>
        /// <param name="value2">もう片方</param>
        /// <returns>早い方（どちらも読めなければ null）</returns>
        private static DateTime? Earlier(string value1, string value2)
        {
            DateTime? time1 = CmnSaml2Response.ToTime(value1);
            DateTime? time2 = CmnSaml2Response.ToTime(value2);

            if (time1 == null) { return time2; }
            if (time2 == null) { return time1; }

            return (((DateTime)time1).Ticks <= ((DateTime)time2).Ticks) ? time1 : time2;
        }

        /// <summary>W3C タイムスタンプを DateTime にする（読めなければ null）</summary>
        /// <param name="value">W3C タイムスタンプ</param>
        /// <returns>DateTime（読めなければ null）</returns>
        private static DateTime? ToTime(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            try
            {
                return FormatConverter.FromW3cTimestamp(value);
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>XML を字下げして文字列にする（目視のため）</summary>
        /// <param name="xml">XmlDocument（null 可）</param>
        /// <returns>字下げした XML（読めなければ元のまま、それも無ければ空）</returns>
        private static string FormatXml(XmlDocument xml)
        {
            if (xml == null)
            {
                return "";
            }

            try
            {
                StringBuilder sb = new StringBuilder();

                XmlWriterSettings settings = new XmlWriterSettings()
                {
                    Indent = true,
                    IndentChars = "  ",
                    OmitXmlDeclaration = true
                };

                using (XmlWriter writer = XmlWriter.Create(sb, settings))
                {
                    xml.WriteTo(writer);
                }

                return sb.ToString();
            }
            catch (Exception)
            {
                return (xml.DocumentElement == null) ? "" : xml.OuterXml;
            }
        }

        #endregion
    }
}
