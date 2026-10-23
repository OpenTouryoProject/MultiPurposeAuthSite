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
//* クラス日本語名  ：SAML2 の応答（SAMLResponse）の検証結果を、この製品の表示にする
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/10  玄人 幸道         新規（#286 の段階 1：鍵と期待Issuerを引数で受ける）
//*  2026/10/12  玄人 幸道         AttributeStatementを読むようにした（#286 の段階 4）
//*  2026/10/12  玄人 幸道         SigAlgの固定をやめ、RSAを受ける版に移した（Open棟梁 #604）
//*  2026/10/13  玄人 幸道         検証鍵にRSAを受けるオーバーロードを足した（#291）
//*  2026/10/14  玄人 幸道         鍵の列を受ける版を足した（#292 の段階 3）
//*  2026/10/22  玄人 幸道         検証を Open棟梁 の SAML2Client.VerifyResponseWithReason に移した（#294）
//**********************************************************************************

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

using Touryo.Infrastructure.Framework.Authentication;

/// <summary>MultiPurposeAuthSite.SamlProviders</summary>
namespace MultiPurposeAuthSite.SamlProviders
{
    /// <summary>
    /// SAML2 の応答（SAMLResponse）を検証した結果を、この製品の表示にする（#286 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **検証の本体は Open棟梁 の `SAML2Client.VerifyResponseWithReason`**（#294）。
    /// **鍵と期待値（Issuer / ACS URL / InResponseTo / RelayState）は、呼び出し側が渡す**
    /// （自己テストは自分、ID 連携は上流）。
    ///
    /// **ここに残るのは、この製品の決め**である。
    ///
    /// | | |
    /// |---|---|
    /// | **理由の文言** | **日本語で、照合した値を添える**（**画面と OPERATION ログ（#253）が使う。`SA-*` が画面の文言を測っている**。#278） |
    /// | **証明書の読み込み** | **設定の `.cer` から検証鍵を作る**（`RsaFromCerFile`） |
    /// | **XML の表示** | **字下げして出す**（目視のため。#246 の項目 3） |
    /// </remarks>
    public class CmnSaml2Response
    {
        #region 判定

        /// <summary>判定（画面に出す）</summary>
        /// <param name="result">`SAML2Client.VerifyResponseWithReason` の結果</param>
        /// <returns>NORMAL_END / ABNORMAL_END</returns>
        /// <remarks>**認証の判断には `IsValid` だけを使う**（Open棟梁 の決め）。</remarks>
        public static string VerdictOf(SAML2VerifyResult result)
        {
            return (result != null && result.IsValid) ? "NORMAL_END" : "ABNORMAL_END";
        }

        /// <summary>判定の理由（画面とログに出す）</summary>
        /// <param name="result">`SAML2Client.VerifyResponseWithReason` の結果</param>
        /// <param name="expectedIssuer">期待した Issuer</param>
        /// <param name="expectedAcsUrl">自分の ACS URL</param>
        /// <param name="expectedInResponseTo">送った AuthnRequest の ID</param>
        /// <returns>理由（日本語）</returns>
        /// <remarks>
        /// **Open棟梁 の `ReasonDescription` は英文で、値を入れない。**
        /// **この製品は、従来どおり日本語で、照合した値を添える**（Open棟梁 #634 の補足 3-2）。
        /// **ID は秘密ではないが、照合の証拠になる**ので出す。
        /// </remarks>
        public static string ReasonOf(SAML2VerifyResult result,
            string expectedIssuer, string expectedAcsUrl, string expectedInResponseTo)
        {
            switch (result.Reason)
            {
                case SAML2VerifyResult.Reasons.Valid:
                    return "署名、Issuer、Audience、Recipient、InResponseTo、RelayState を照合した。";

                case SAML2VerifyResult.Reasons.NoResponse:
                    return "SAMLResponse が無い。";

                case SAML2VerifyResult.Reasons.NoSigAlg:
                    return "SigAlg が無いため、検証していない。";

                case SAML2VerifyResult.Reasons.NoKey:
                    // **鍵が無ければ検証できない。** **通してはならない。**
                    return "署名を検証する証明書が設定されていない。";

                case SAML2VerifyResult.Reasons.Unreadable:
                    return "応答を読めなかった。";

                case SAML2VerifyResult.Reasons.ErrorStatus:
                    return "エラー応答である（StatusCode=" + result.StatusCode + "）。";

                case SAML2VerifyResult.Reasons.Expired:
                    if (result.NotExpired == false)
                    {
                        return "アサーションの有効期限が切れている（NotOnOrAfter="
                            + CmnSaml2Response.NotOnOrAfterOf(result) + "）。";
                    }

                    // **NotOnOrAfter が無い・読めない**（従来どおり、署名の検証で落ちたものとして扱う）。
                    return "署名または XML（スキーマ）の検証で落ちた。";

                case SAML2VerifyResult.Reasons.IssuerMismatch:
                    return "Issuer が期待値と違う : "
                        + CmnSaml2Response.OrNone(result.Issuer) + "（期待 : " + expectedIssuer + "）";

                case SAML2VerifyResult.Reasons.AudienceMismatch:
                    return "Audience が自分の ACS URL と違う : "
                        + CmnSaml2Response.OrNone(result.Audience) + "（期待 : " + expectedAcsUrl + "）";

                case SAML2VerifyResult.Reasons.RecipientMismatch:
                    return "Recipient が自分の ACS URL と違う : "
                        + CmnSaml2Response.OrNone(result.Recipient) + "（期待 : " + expectedAcsUrl + "）";

                case SAML2VerifyResult.Reasons.InResponseToMismatch:
                    return "InResponseTo が、送った要求の ID と違う : "
                        + CmnSaml2Response.OrNone(result.InResponseTo) + "（期待 : " + expectedInResponseTo + "）";

                case SAML2VerifyResult.Reasons.RelayStateMismatch:
                    return "RelayState が、送った state と違う。";

                default:
                    // SignatureInvalid / Conflicted（Response と Assertion の食い違い）
                    return "署名または XML（スキーマ）の検証で落ちた。";
            }
        }

        #endregion

        #region 表示

        /// <summary>バインディング（どう受け取ったか）</summary>
        /// <param name="result">`SAML2Client.VerifyResponseWithReason` の結果</param>
        /// <returns>表示する文字列</returns>
        public static string BindingOf(SAML2VerifyResult result)
        {
            return result.IsRedirect
                ? "Redirect（GET。署名はクエリ文字列に付く）" : "POST（署名は XML の中）";
        }

        /// <summary>NotOnOrAfter（表示する形。無ければ空）</summary>
        /// <param name="result">`SAML2Client.VerifyResponseWithReason` の結果</param>
        /// <returns>yyyy-MM-dd HH:mm:ss</returns>
        public static string NotOnOrAfterOf(SAML2VerifyResult result)
        {
            return (result.NotOnOrAfter == null)
                ? "" : ((DateTime)result.NotOnOrAfter).ToString("yyyy-MM-dd HH:mm:ss");
        }

        /// <summary>XML を字下げして文字列にする（目視のため）</summary>
        /// <param name="xml">XmlDocument（null 可）</param>
        /// <returns>字下げした XML（読めなければ元のまま、それも無ければ空）</returns>
        public static string FormatXml(XmlDocument xml)
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

        #region 検証鍵

        /// <summary>`.cer` のファイルから、検証鍵（RSA）を作る</summary>
        /// <param name="cerFilePath">`.cer` のパス（空なら null を返す）</param>
        /// <returns>RSA（読めなければ null）</returns>
        /// <remarks>
        /// **証明書の読み込みはターゲットで分ける**（`Extensions/Sts/Helper.cs` と同じ流儀）。
        /// **`new X509Certificate2(path)` は net10.0 で旧形式**（SYSLIB0057）であり、
        /// **`X509CertificateLoader` は net48 に無い。**
        ///
        /// **破棄しない。** **`GetRSAPublicKey()` の鍵は証明書に紐づく**ので、
        /// **先に破棄すると、この後の検証で使えない。**
        ///
        /// **読む場所を 1 か所に寄せてある**（#291）。
        /// **設定の `.cer` を読むのは、ここと、ID 連携の口（メタデータが引けなかったとき）である。**
        /// </remarks>
        public static RSA RsaFromCerFile(string cerFilePath)
        {
            if (string.IsNullOrEmpty(cerFilePath))
            {
                return null;
            }

            try
            {
#if NETFX
                X509Certificate2 x509 = new X509Certificate2(cerFilePath);
#else
                X509Certificate2 x509 = X509CertificateLoader.LoadCertificateFromFile(cerFilePath);
#endif
                return x509.GetRSAPublicKey();
            }
            catch (Exception)
            {
                // **読めない証明書は、鍵が無いものとして扱う。**
                return null;
            }
        }

        #endregion

        #region private

        /// <summary>空なら「（無し）」</summary>
        /// <param name="value">値</param>
        /// <returns>表示する文字列</returns>
        private static string OrNone(string value)
        {
            return string.IsNullOrEmpty(value) ? "（無し）" : value;
        }

        #endregion
    }
}
