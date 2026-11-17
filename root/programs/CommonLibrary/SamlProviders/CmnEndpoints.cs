//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
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
//* クラス名        ：CmnEndpoints
//* クラス日本語名  ：CmnEndpoints（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/06/03  西野 大介         新規
//*  2020/01/07  西野 大介         PPID対応実施
//*  2026/10/07  玄人 幸道         ACS URL の不一致を登録値へのエラー応答にした（#276）
//*  2026/10/07  玄人 幸道         アサーションの有効期限の単位を直した（分→秒。#276）
//*  2026/10/07  玄人 幸道         エラー応答にAssertionを組み込まないようにした（#278）
//*  2026/10/12  玄人 幸道         アサーションにAttributeStatementを足した（#286 の段階 4）
//*  2026/11/16  玄人 幸道         要求の ID は NCName の形だけを使うようにした（#390）
//*  2026/11/16  玄人 幸道         NameID に埋め込めない文字を含む値なら、アサーションを作らないようにした（#390）
//*  2026/11/16  玄人 幸道         要求の Destination を受けた口の URL と照合し、合わなければ捨てるようにした（#392）
//*  2026/11/17  玄人 幸道         応答の Audience を、ACS の URL から SP の entityID（要求の Issuer）にした（SAML Profiles §4.1.4.2。OpenTouryo#693。#389）
//*  2026/11/17  玄人 幸道         鍵を登録していない SP の、署名の無い要求を断るようにした（メタデータの WantAuthnRequestsSigned=true と揃えた。#400）
//**********************************************************************************

#if NETFX
using MultiPurposeAuthSite.Entity;
#else
//
#endif

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util;
using MultiPurposeAuthSite.Util.Sts;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Xml;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Log;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.SamlProviders
{
    /// <summary>CmnEndpoints</summary>
    public class CmnEndpoints
    {
        /// <summary>VerifySamlRequest</summary>
        /// <param name="queryString">string（Redirect Binding のときのクエリ文字列。POST なら空）</param>
        /// <param name="samlRequest">string（POST Binding のときの SAMLRequest）</param>
        /// <param name="iss">out string（要求の Issuer。この製品では client_id）</param>
        /// <param name="inResponseTo">out string（要求の ID。NCName の形でなければ空文字。#390）</param>
        /// <param name="samlRequest2">out XmlDocument（要求。読めなければ null）</param>
        /// <param name="discard">
        /// out bool（**要求を捨てる**か。`Destination` が受けた口と合わない・署名した要求に無い。#392）。
        /// **true なら、SP へ応答を返さず、エラー画面にする**（SAML Core 3.2.1「the request MUST be discarded」）
        /// </param>
        /// <returns>検証できたか</returns>
        /// <remarks>
        /// **検証は Open棟梁 の `SAML2Client.VerifyRequest`**（署名と XML の構造。#294）。
        /// **鍵は、要求の Issuer（＝ client_id）の登録から引く。**
        ///
        /// **署名を確かめられない要求は断る**（鍵を登録していない SP の要求を含む。#400）。
        /// **以前は、鍵が無い SP の要求を、署名を確かめずに通していた**（この製品の決め。Open棟梁 #634 の補足 3-5）。
        /// **メタデータは `WantAuthnRequestsSigned="true"` を広告している**（Open棟梁 の部品が固定で埋め込む）ので、振る舞いを揃えた。
        /// **設定で以前の受け方に戻す分岐は作らない**（#400 で決めた）。断った要求には、登録済みの ACS URL へ Requester のエラー応答を返す（呼び出し側）。
        ///
        /// **`Destination` は、ここで照合する**（Open棟梁 の `VerifyRequest` は見ない。#392）。
        /// </remarks>
        public static bool VerifySamlRequest(
            string queryString, string samlRequest,
            out string iss, out string inResponseTo, out XmlDocument samlRequest2, out bool discard)
        {
            bool hasNoKey = false;
            discard = false;

            bool verified = SAML2Client.VerifyRequest(queryString, samlRequest,
                requestIss =>
                {
                    RSA rsa = CmnEndpoints.RsaOf(CmnEndpoints.ClientIdOf(requestIss));
                    hasNoKey = (rsa == null);
                    return hasNoKey ? null : new RSA[] { rsa };
                },
                out iss, out inResponseTo, out samlRequest2);

            // **署名を検証できたか**（鍵が無くて通す要求は、署名を確かめていない）。
            bool signatureVerified = verified;

            // - iss : 当該IdP/Stsの仕様（client_idを流用するので）
            iss = CmnEndpoints.ClientIdOf(iss);

            // **Destination の照合**（#392）
            //   - **在れば、受けた口の URL と一致すること**（SAML Core 3.2.1。署名の有無によらない）
            //   - **署名を検証できた要求には、在ること**（SAML Bindings 3.4.5.2・3.5.5.2）
            //   **合わなければ、要求を捨てる**（SP へ応答を返さない。3.2.1「MUST be discarded」）。
            if (samlRequest2 != null && samlRequest2.DocumentElement != null)
            {
                XmlElement root = samlRequest2.DocumentElement;
                bool hasDestination = root.HasAttribute(SAML2Const.AttrDestination);

                if ((hasDestination && root.GetAttribute(SAML2Const.AttrDestination) != CmnEndpoints.Saml2RequestUrl)
                    || (!hasDestination && signatureVerified))
                {
                    Logging.MyOperationTrace(string.Format(
                        "SAML2 request was discarded: the Destination {0} (Issuer: {1}).",
                        hasDestination ? "does not match the SAML2 endpoint" : "is missing in the signed request",
                        LogSanitizer.Sanitize(iss)));

                    discard = true;
                    return false;
                }
            }

            if (!verified && hasNoKey)
            {
                // **鍵が無い SP の要求は、署名を確かめられないので断る**（#400。以前は通していた）。
                //   **署名の検証の失敗と見分けられるよう、別に残す。**
                Logging.MyOperationTrace(string.Format(
                    "SAML2 request was refused: no key is registered to verify the signature (Issuer: {0}).",
                    LogSanitizer.Sanitize(iss)));
            }

            // **要求の ID は、xs:ID（NCName）の形のものだけを使う**（SAML Core 1.3.4。#390）。
            //   **ID は送る側が決める値で、署名の検証より前に取り出される。**
            //   **この値は、IdP が署名する応答の InResponseTo に入る**（成功の応答にも、エラー応答にも）。
            //   **Open棟梁 の部品は、値を文字列の置換で応答に埋め込む**ので、
            //   形の合わない値は、検証の失敗として扱い、応答にも使わない。
            if (!CmnEndpoints.IsNCName(inResponseTo))
            {
                // **署名の検証の失敗と見分けられるよう、別に残す**（値は書かない）。
                Logging.MyOperationTrace(string.Format(
                    "SAML2 request was refused: the ID is not an NCName (Issuer: {0}).",
                    LogSanitizer.Sanitize(iss)));

                inResponseTo = "";
                verified = false;
            }

            return verified;
        }

        /// <summary>レスポンス作成</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="authnContextClassRef">SAML2Enum.AuthnContextClassRef</param>
        /// <param name="statusCode">SAML2Enum.StatusCode</param>
        /// <param name="iss">string ※ Requestのissを指定</param>
        /// <param name="relayState">string</param>
        /// <param name="inResponseTo">string</param>
        /// <param name="rtnUrl">out string</param>
        /// <param name="samlResponse">out string</param>
        /// <param name="queryString">out string</param>
        /// <param name="samlRequest">XmlDocument</param>
        /// <param name="samlNsMgr">XmlNamespaceManager</param>
        /// <param name="hashAlgorithmName">HashAlgorithmName</param>
        /// <returns>
        /// SAML2Enum.ProtocolBinding（返す先のバインディング）。
        /// **null は「応答を返す先が決まらない」**ことを表す（#276）。
        /// </returns>
        public static SAML2Enum.ProtocolBinding? CreateSamlResponse(
            ClaimsIdentity identity,
            SAML2Enum.AuthnContextClassRef authnContextClassRef,
            SAML2Enum.StatusCode statusCode,
            string iss, string relayState, string inResponseTo,
            out string rtnUrl, out string samlResponse, out string queryString,
            XmlDocument samlRequest, XmlNamespaceManager samlNsMgr,
            HashAlgorithmName? hashAlgorithmName = null) // 既定値の変更 SHA1 → SHA256
        {
            string rtnProtocol = "";
            string nameIdPolicy = "";

            rtnUrl = "";
            samlResponse = "";
            queryString = "";

            // DigitalSignX509
            HashAlgorithmName han = hashAlgorithmName ?? HashAlgorithmName.SHA256;
            DigitalSignX509 dsX509 = new DigitalSignX509(CmnServerParams.RsaPfxFilePath, CmnServerParams.RsaPfxPassword, han);

            // rtnUrl
            //  **返す先は、常に事前登録の値である**（#276）。
            //    **要求に書かれた ACS URL は、登録値との照合にしか使わない。**
            //    （要求の値をそのまま使うと、任意の URL へアサーションを飛ばせられる。）
            string temp1 = SAML2Bindings.GetAssertionConsumerServiceURLInRequest(samlRequest, samlNsMgr);
            string temp2 = Helper.GetInstance().GetAssertionConsumerServiceURL(iss);

            if (string.IsNullOrEmpty(temp2))
            {
                // **事前登録が無い**（iss が未登録、または ACS URL を登録していない）。
                //   **応答を返す先が決まらないので、応答しない**（SAML Core 3.2.1）。
                return null;
            }

            if (!string.IsNullOrEmpty(temp1) && temp1 != temp2)
            {
                // **要求の ACS URL が登録値と違う。**
                //   **登録値へ Requester のエラー応答を返す。**
                //
                //   **以前は null を返していた**が、**呼び出し側は
                //   `== HttpRedirect` で分岐していた**ので、
                //   **null が POST 側に落ち、action も SAMLResponse も空の
                //   自動送信フォームが返っていた**（#276）。
                statusCode = SAML2Enum.StatusCode.Requester;
            }

            rtnUrl = temp2; // 事前登録の値

            // 事前登録されている。
            if (rtnUrl.ToLower() == Const.TestSelfSaml)
            {
                // Authorization Codeグラント種別のテスト用のセルフRedirectエンドポイント
                rtnUrl = Config.OAuth2ClientEndpointsRootURI + Config.Saml2ResponseEndpoint;
            }

            // NameIDPolicyFormat
            nameIdPolicy = SAML2Bindings.GetNameIDPolicyFormatInRequest(samlRequest, samlNsMgr);
            
            // 文字列から配列に変換
            SAML2Enum.NameIDFormat? nameIDFormat = null;
            SAML2Enum.StringToEnum(nameIdPolicy, out nameIDFormat);
            if (!nameIDFormat.HasValue) nameIDFormat = SAML2Enum.NameIDFormat.Unspecified;

            // rtnProtocol
            rtnProtocol = SAML2Bindings.GetProtocolBindingInRequest(samlRequest, samlNsMgr);
            SAML2Enum.ProtocolBinding? protocolBinding = null;
            SAML2Enum.StringToEnum(rtnProtocol, out protocolBinding);
            if (!protocolBinding.HasValue) protocolBinding = SAML2Enum.ProtocolBinding.HttpRedirect;

            // nameIDFormat.Valueに合わせて処理（PPID）
            //  **sub の算出も属性も、エラー応答では要らない値**（Assertion を組み込まない。#278）。
            string sub = "";
            List<Tuple<string, string, string, string>> attributes = null;

            if (statusCode == SAML2Enum.StatusCode.Success)
            {
                //  **利用者も受け取る**（#286 の段階 4）。**属性に入れる値を、引き直さずに使う。**
                ApplicationUser user = null;
                sub = PPIDExtension.GetSubForSAML2(
                    iss, identity.Name, nameIDFormat.Value, out user);

                // **メアドと利用者名を属性で返す**（#286 の段階 4）。
                if (user != null)
                {
                    attributes = CmnEndpoints.AttributesOf(user.Email, user.UserName, user.EmailConfirmed);
                }

                // **NameID に `<`・`&`・`{`・XML で使えない文字を含む値は入れない**（#390）。
                //   **Open棟梁 の部品は、NameID を文字列の置換で要素の中に埋め込む**ので、
                //   これらの文字はアサーションの構造や値を変えるか、XML を壊す。
                //   **EmailAddress の形式では、利用者のメアドがそのまま入る**（net10.0 版の検証は `<` を通す）。
                //   **エスケープはしない**（部品が値を DOM の API で入れるようになったとき、二重になるため）。
                //   **アサーションを作らず、Responder のエラー応答にする**（SAML Core 3.2.2.2）。
                if (CmnEndpoints.HasXmlMarkup(sub))
                {
                    Logging.MyOperationTrace(string.Format(
                        "SAML2 response was not issued: the NameID ({0}) contains characters that cannot be embedded (client_id: {1}).",
                        nameIDFormat.Value, LogSanitizer.Sanitize(iss)));

                    statusCode = SAML2Enum.StatusCode.Responder;
                    sub = "";
                    attributes = null;
                }
            }

            //  **応答の組み立てと署名は Open棟梁 の `SAML2Client`**（#294）。
            //    **返す先・NameID・属性・Binding の決めは、ここに残る。**
            //    **有効期間は `Config` の値を渡す**（無ければ id_token の期間に倒す。Open棟梁 #634 の補足 3-4）。
            double expiresInSeconds = Config.Saml2AssertionExpireTimeSpanFromMinutes * 60;

            //  **Audience は、SP の entityID（要求の Issuer そのもの）**（SAML Profiles §4.1.4.2。#389）。
            //    **`iss` は "http://" を外した client_id** なので使わない（`ClientIdOf`）。要求の Issuer を読み直す。
            //    **以前は ACS の URL を入れていた**（Open棟梁 の `audience` を受けない版）。**設定で戻す分岐は作らない**（#389 で決めた）。
            //    要求の Issuer は登録と照合済み（登録が無ければ、上で応答しない）。
            string audience = SAML2Bindings.GetIssuerInRequest(samlRequest, samlNsMgr);

            // 返しのProtocol Binding
            switch (protocolBinding)
            {
                case SAML2Enum.ProtocolBinding.HttpRedirect:
                    // SamlResponseのエンコと、QueryStringを生成（ + 署名）
                    queryString = SAML2Client.CreateRedirectResponse(
                        CmnServerParams.IssuerId, rtnUrl, audience, inResponseTo, statusCode,
                        sub, nameIDFormat.Value, authnContextClassRef,
                        expiresInSeconds, attributes, relayState, dsX509);
                    break;
                case SAML2Enum.ProtocolBinding.HttpPost:
                    // SamlResponseのエンコと署名
                    samlResponse = SAML2Client.CreatePostResponse(
                        CmnServerParams.IssuerId, rtnUrl, audience, inResponseTo, statusCode,
                        sub, nameIDFormat.Value, authnContextClassRef,
                        expiresInSeconds, attributes, dsX509.X509Certificate.GetRSAPrivateKey());
                    break;
            }

            return protocolBinding;
        }

        #region private

        /// <summary>この IdP の SAML2 の口の URL（要求の `Destination` と比べる。#392）</summary>
        /// <remarks>
        /// **自己テスト・ID 連携の SP が `Destination` に入れる値と同じ**（#391）。
        /// **一字一句で比べる**（事前登録の ACS URL の照合と同じ扱い。#276）。
        /// </remarks>
        private static string Saml2RequestUrl
        {
            get
            {
                return Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;
            }
        }

        /// <summary>要求の Issuer から、client_id を作る</summary>
        /// <param name="iss">要求の Issuer</param>
        /// <returns>client_id</returns>
        /// <remarks>当該IdP/Stsの仕様（client_idを流用するので）</remarks>
        private static string ClientIdOf(string iss)
        {
            return (iss ?? "").Replace("http://", "");
        }

        /// <summary>値が NCName（xs:ID の字句の形）か</summary>
        /// <param name="value">値</param>
        /// <returns>NCName なら true（null・空は false）</returns>
        /// <remarks>
        /// **NCName は、引用符・`&lt;`・`&amp;`・空白・`:` を含まない**（Namespaces in XML 1.0 §3）。
        /// </remarks>
        private static bool IsNCName(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            try
            {
                XmlConvert.VerifyNCName(value);
                return true;
            }
            catch (XmlException)
            {
                return false;
            }
        }

        /// <summary>テンプレートの要素の中身に、文字列の置換で入れられない値か</summary>
        /// <param name="value">値</param>
        /// <returns>入れられなければ true</returns>
        /// <remarks>
        /// - `&lt;`・`&amp;`：XML の構造を変えるか壊す
        /// - `{`：部品は置換を順に行うので、後の置換の印（`{Recipient}` など）が書き換わる
        /// - XML で使えない文字（制御文字など）：XML を壊す
        /// </remarks>
        private static bool HasXmlMarkup(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            if (value.IndexOfAny(new char[] { '<', '&', '{' }) >= 0)
            {
                return true;
            }

            try
            {
                XmlConvert.VerifyXmlChars(value);
                return false;
            }
            catch (XmlException)
            {
                return true;
            }
        }

        /// <summary>client_id に登録された、署名を検証する鍵（RSA）</summary>
        /// <param name="clientId">client_id</param>
        /// <returns>RSA（登録が無ければ null）</returns>
        private static RSA RsaOf(string clientId)
        {
            // rsa from iss
            string pubKey = Helper.GetInstance().GetJwkRsaPublickey(clientId);

            if (string.IsNullOrEmpty(pubKey))
            {
                return null;
            }

            pubKey = CustomEncode.ByteToString(
                CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

            // 鍵変換
            return new RsaPublicKeyConverter(JWS_RSA.RS._256).JwkToProvider(pubKey);
        }

        /// <summary>アサーションに入れる属性（メアド・email_verified・利用者名）</summary>
        /// <param name="email">メアド</param>
        /// <param name="userName">利用者名</param>
        /// <param name="emailVerified">メアドを確かめたか</param>
        /// <returns>属性の並び（Name, FriendlyName, NameFormat, 値）</returns>
        /// <remarks>
        /// **名前は Open棟梁 の `SAML2Const` が持つ**（読む側の `SAML2Attributes` と同じもの）。
        /// **`email_verified` は、メアドを出すときだけ添える。**
        /// </remarks>
        private static List<Tuple<string, string, string, string>> AttributesOf(
            string email, string userName, bool emailVerified)
        {
            List<Tuple<string, string, string, string>> ret = new List<Tuple<string, string, string, string>>();

            if (!string.IsNullOrEmpty(email))
            {
                ret.Add(Tuple.Create(SAML2Const.UrnOidMail,
                    SAML2Const.FriendlyNameMail, SAML2Const.UrnAttrNameFormatUri, email));
                ret.Add(Tuple.Create(OAuth2AndOIDCConst.email_verified,
                    "", SAML2Const.UrnAttrNameFormatBasic, emailVerified ? "true" : "false"));
            }

            if (!string.IsNullOrEmpty(userName))
            {
                ret.Add(Tuple.Create(SAML2Const.UrnOidUid,
                    SAML2Const.FriendlyNameUid, SAML2Const.UrnAttrNameFormatUri, userName));
            }

            return ret;
        }

        #endregion

        // VerifySamlResponseはクライアントライブラリなので、
        // Touryo.Infrastructure.Framework.Authenticationに実装
    }
}
