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
//* クラス名        ：Saml2
//* クラス日本語名  ：SAML2 の要求を組み立て、応答を読む（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/07  玄人 幸道         新規（#275）
//*  2026/10/11  玄人 幸道         FromRedirectQuery でSAMLRequestも読めるようにした（#286 の段階 3）
//*  2026/10/12  玄人 幸道         アサーションの属性を読むようにした（#286 の段階 4）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Xml;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// SAML2 の要求を組み立て、応答を読む（#275）。
    /// </summary>
    /// <remarks>
    /// **自己テストのボタンでは測れないものを測るために在る。**
    ///
    /// | 測れないもの | なぜ |
    /// |---|---|
    /// | `NameIDPolicy` の値ごとの違い | **ボタンは `Unspecified` 固定** |
    /// | ACS URL の不一致 | ボタンは登録値を送る |
    /// | 未登録の `Issuer` | 同上 |
    /// | 壊れた `SAMLRequest` | 同上 |
    ///
    /// **署名は付けない。**
    /// **`jwk_rsa_publickey` を登録していないクライアントは、署名の無い要求を通す**
    /// （`SamlProviders/CmnEndpoints.VerifySamlRequest` の「鍵がない場合は、通す」）。
    /// **E2E 専用の `TestClient_21` / `TestClient_22` が、その形で登録されている**（`KnownClients`）。
    ///
    /// **鍵を登録しているクライアント（`TestClient`）へ送れば、署名の検証が落ちることを measure できる。**
    /// </remarks>
    public static class Saml2
    {
        #region 名前空間

        /// <summary>samlp（protocol）</summary>
        public const string UrnProtocol = "urn:oasis:names:tc:SAML:2.0:protocol";

        /// <summary>saml（assertion）</summary>
        public const string UrnAssertion = "urn:oasis:names:tc:SAML:2.0:assertion";

        /// <summary>HTTP-Redirect Binding</summary>
        public const string BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

        /// <summary>HTTP-POST Binding</summary>
        public const string BindingPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

        /// <summary>NameIDFormat : unspecified</summary>
        public const string FormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

        /// <summary>NameIDFormat : emailAddress</summary>
        public const string FormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

        /// <summary>NameIDFormat : persistent</summary>
        public const string FormatPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

        /// <summary>StatusCode : Success</summary>
        public const string StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";

        /// <summary>StatusCode : Requester（要求側の誤り）</summary>
        public const string StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester";

        /// <summary>StatusCode : Responder（応答側の誤り）</summary>
        public const string StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder";

        #endregion

        #region 要求を組み立てる

        /// <summary>AuthnRequest の XML を組み立てる（#275）</summary>
        /// <param name="id">ID（省略すると作る。応答の InResponseTo と照合できる）</param>
        /// <param name="issuer">Issuer（IdP は "http://" を外して client_id として扱う）</param>
        /// <param name="nameIdFormat">NameIDPolicy の Format（null なら要素を入れない）</param>
        /// <param name="protocolBinding">応答の受け取り方（null なら属性を入れない＝ IdP の既定は Redirect）</param>
        /// <param name="acsUrl">AssertionConsumerServiceURL（null なら属性を入れない＝登録値が使われる）</param>
        /// <returns>XML</returns>
        /// <remarks>
        /// **Open棟梁 の `SAML2Const.RequestTemplate` と同じ形**にしてある。
        /// **XPath が絶対パス（`/samlp:AuthnRequest`）**なので、根の要素名と接頭辞を変えられない。
        /// </remarks>
        public static string BuildAuthnRequest(
            string id, string issuer,
            string nameIdFormat = FormatUnspecified,
            string protocolBinding = null, string acsUrl = null)
        {
            StringBuilder sb = new StringBuilder();

            sb.Append("<samlp:AuthnRequest");
            sb.Append(" Version=\"2.0\" ID=\"" + Xml(id) + "\"");
            sb.Append(" IssueInstant=\"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\"");

            if (protocolBinding != null)
            {
                sb.Append(" ProtocolBinding=\"" + Xml(protocolBinding) + "\"");
            }

            if (acsUrl != null)
            {
                sb.Append(" AssertionConsumerServiceURL=\"" + Xml(acsUrl) + "\"");
            }

            sb.Append(" xmlns:saml=\"" + UrnAssertion + "\"");
            sb.Append(" xmlns:samlp=\"" + UrnProtocol + "\">");
            sb.Append("<saml:Issuer>" + Xml(issuer) + "</saml:Issuer>");

            if (nameIdFormat != null)
            {
                sb.Append("<samlp:NameIDPolicy Format=\"" + Xml(nameIdFormat) + "\" />");
            }

            sb.Append("</samlp:AuthnRequest>");

            return sb.ToString();
        }

        /// <summary>ID を作る（SAML の ID は先頭が英字でなければならない）</summary>
        /// <returns>ID</returns>
        public static string NewId()
        {
            return "e2e" + Guid.NewGuid().ToString("N");
        }

        /// <summary>Redirect Binding のクエリ文字列にする（#275）</summary>
        /// <param name="xml">AuthnRequest の XML</param>
        /// <param name="relayState">RelayState（空なら付けない）</param>
        /// <returns>クエリ文字列（先頭に ? は付かない）</returns>
        /// <remarks>
        /// **DEFLATE（生。zlib のヘッダを付けない）→ base64 → URL 符号化**
        /// （SAML 2.0 Bindings 3.4.4.1）。
        /// **署名は付けない**（この基盤は署名を作らない。クラスの説明を参照）。
        /// </remarks>
        public static string ToRedirectQuery(string xml, string relayState = null)
        {
            string value = Uri.EscapeDataString(Convert.ToBase64String(Deflate(xml)));

            string query = "SAMLRequest=" + value;

            if (!string.IsNullOrEmpty(relayState))
            {
                query += "&RelayState=" + Uri.EscapeDataString(relayState);
            }

            return query;
        }

        /// <summary>POST Binding の SAMLRequest の値にする（#275）</summary>
        /// <param name="xml">AuthnRequest の XML</param>
        /// <returns>base64</returns>
        /// <remarks>**POST Binding は圧縮しない**（SAML 2.0 Bindings 3.5.4）。</remarks>
        public static string ToPostValue(string xml)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));
        }

        #endregion

        #region 応答を読む

        /// <summary>POST Binding で返った SAMLResponse を XML に戻す</summary>
        /// <param name="value">base64</param>
        /// <returns>XML（戻せなければ null）</returns>
        public static string FromPostValue(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(value));
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Redirect Binding のクエリ文字列から、SAMLResponse / SAMLRequest を XML に戻す。
        /// </summary>
        /// <param name="urlOrQuery">URL でもクエリ文字列でもよい</param>
        /// <param name="name">パラメタの名前（既定は `SAMLResponse`）</param>
        /// <returns>XML（戻せなければ null）</returns>
        /// <remarks>
        /// **`SAMLRequest` も同じ符号化である**（deflate ＋ base64）。
        /// **下流が送る `AuthnRequest` を読むのに使う**（#286 の段階 3）。
        /// </remarks>
        public static string FromRedirectQuery(string urlOrQuery, string name = "SAMLResponse")
        {
            string value = QueryValue(urlOrQuery, name);

            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            try
            {
                return Encoding.UTF8.GetString(Inflate(Convert.FromBase64String(value)));
            }
            catch
            {
                return null;
            }
        }

        /// <summary>クエリ文字列から 1 つの値を取る（#275）</summary>
        /// <param name="urlOrQuery">URL でもクエリ文字列でもよい</param>
        /// <param name="name">名前</param>
        /// <returns>値（無ければ null）</returns>
        public static string QueryValue(string urlOrQuery, string name)
        {
            if (string.IsNullOrEmpty(urlOrQuery))
            {
                return null;
            }

            string query = urlOrQuery;
            int q = query.IndexOf('?');

            if (q >= 0)
            {
                query = query.Substring(q + 1);
            }

            foreach (string pair in query.Split('&'))
            {
                int eq = pair.IndexOf('=');

                if (eq < 0)
                {
                    continue;
                }

                if (Uri.UnescapeDataString(pair.Substring(0, eq)) == name)
                {
                    return Uri.UnescapeDataString(pair.Substring(eq + 1).Replace("+", "%20"));
                }
            }

            return null;
        }

        /// <summary>応答の XML から、よく見る値を読む（#275）</summary>
        /// <param name="xml">XML</param>
        /// <returns>Saml2Response（読めなければ null）</returns>
        public static Saml2Response ReadResponse(string xml)
        {
            if (string.IsNullOrEmpty(xml))
            {
                return null;
            }

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = false;

            try
            {
                doc.LoadXml(xml);
            }
            catch
            {
                return null;
            }

            XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("samlp", UrnProtocol);
            ns.AddNamespace("saml", UrnAssertion);

            return new Saml2Response()
            {
                Xml = xml,
                StatusCode = Attr(doc, ns, "/samlp:Response/samlp:Status/samlp:StatusCode", "Value"),
                Destination = Attr(doc, ns, "/samlp:Response", "Destination"),
                InResponseTo = Attr(doc, ns, "/samlp:Response", "InResponseTo"),
                Issuer = Text(doc, ns, "/samlp:Response/saml:Issuer"),
                NameId = Text(doc, ns, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"),
                NameIdFormat = Attr(doc, ns,
                    "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", "Format"),
                Audience = Text(doc, ns,
                    "/samlp:Response/saml:Assertion/saml:Conditions"
                    + "/saml:AudienceRestriction/saml:Audience"),
                Recipient = Attr(doc, ns,
                    "/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation"
                    + "/saml:SubjectConfirmationData", "Recipient"),
                NotOnOrAfter = Attr(doc, ns,
                    "/samlp:Response/saml:Assertion/saml:Conditions", "NotOnOrAfter"),
                HasAssertion = (doc.SelectSingleNode(
                    "/samlp:Response/saml:Assertion", ns) != null),
                HasSignature = (doc.SelectSingleNode("//*[local-name()='SignatureValue']") != null),
                Attributes = Saml2.ReadAttributes(doc, ns)
            };
        }

        /// <summary>
        /// アサーションの `AttributeStatement` を読む（#286 の段階 4）。
        /// </summary>
        /// <param name="doc">応答の XmlDocument</param>
        /// <param name="ns">XmlNamespaceManager</param>
        /// <returns>
        /// 属性（鍵は `Name`。値は最初の `AttributeValue`）。
        /// **無ければ空の辞書**（null は返さない）。
        /// </returns>
        /// <remarks>
        /// **`Name` だけを鍵にする**（`FriendlyName` は別に持つ）。
        /// **出す側が何を名乗っているかを測る**ので、
        /// **製品側（`CmnSamlAttributes.Read`）のような別名の解決はしない。**
        /// </remarks>
        private static Dictionary<string, string> ReadAttributes(
            XmlDocument doc, XmlNamespaceManager ns)
        {
            Dictionary<string, string> ret = new Dictionary<string, string>();

            XmlNodeList attributes = doc.SelectNodes(
                "/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute", ns);

            if (attributes == null)
            {
                return ret;
            }

            foreach (XmlNode attr in attributes)
            {
                string name = Saml2.NodeAttr(attr, "Name");
                XmlNode value = attr.SelectSingleNode("saml:AttributeValue", ns);

                if (string.IsNullOrEmpty(name) || value == null || ret.ContainsKey(name))
                {
                    continue;
                }

                ret.Add(name, value.InnerText);
            }

            return ret;
        }

        /// <summary>
        /// アサーションの属性の `FriendlyName` と `NameFormat` を読む（#286 の段階 4）。
        /// </summary>
        /// <param name="xml">応答の XML</param>
        /// <param name="name">属性の `Name`</param>
        /// <param name="friendlyName">out FriendlyName（無ければ空）</param>
        /// <param name="nameFormat">out NameFormat（同上）</param>
        /// <returns>その `Name` の属性が在れば true</returns>
        public static bool TryReadAttributeNames(
            string xml, string name, out string friendlyName, out string nameFormat)
        {
            friendlyName = "";
            nameFormat = "";

            if (string.IsNullOrEmpty(xml))
            {
                return false;
            }

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = false;

            try
            {
                doc.LoadXml(xml);
            }
            catch
            {
                return false;
            }

            XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("samlp", UrnProtocol);
            ns.AddNamespace("saml", UrnAssertion);

            XmlNode attr = doc.SelectSingleNode(
                "/samlp:Response/saml:Assertion/saml:AttributeStatement"
                + "/saml:Attribute[@Name='" + name + "']", ns);

            if (attr == null)
            {
                return false;
            }

            friendlyName = Saml2.NodeAttr(attr, "FriendlyName");
            nameFormat = Saml2.NodeAttr(attr, "NameFormat");

            return true;
        }

        /// <summary>XML の属性値を読む（無ければ空）</summary>
        /// <param name="node">XmlNode</param>
        /// <param name="name">属性の名前</param>
        /// <returns>値</returns>
        private static string NodeAttr(XmlNode node, string name)
        {
            if (node == null || node.Attributes == null)
            {
                return "";
            }

            XmlNode attr = node.Attributes[name];

            return (attr == null) ? "" : attr.Value;
        }

        #endregion

        #region 補助

        /// <summary>XML の属性値として安全にする</summary>
        /// <param name="value">値</param>
        /// <returns>符号化した値</returns>
        private static string Xml(string value)
        {
            if (value == null)
            {
                return "";
            }

            return value
                .Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
                .Replace("\"", "&quot;").Replace("'", "&apos;");
        }

        /// <summary>DEFLATE（生）</summary>
        /// <param name="text">文字列</param>
        /// <returns>byte[]</returns>
        private static byte[] Deflate(string text)
        {
            byte[] raw = Encoding.UTF8.GetBytes(text);

            using (MemoryStream ms = new MemoryStream())
            {
                using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Compress, true))
                {
                    ds.Write(raw, 0, raw.Length);
                }

                return ms.ToArray();
            }
        }

        /// <summary>INFLATE（生）</summary>
        /// <param name="bytes">byte[]</param>
        /// <returns>byte[]</returns>
        private static byte[] Inflate(byte[] bytes)
        {
            using (MemoryStream src = new MemoryStream(bytes))
            using (DeflateStream ds = new DeflateStream(src, CompressionMode.Decompress))
            using (MemoryStream dst = new MemoryStream())
            {
                ds.CopyTo(dst);
                return dst.ToArray();
            }
        }

        /// <summary>XPath で属性を読む</summary>
        /// <param name="doc">XmlDocument</param>
        /// <param name="ns">XmlNamespaceManager</param>
        /// <param name="xpath">XPath</param>
        /// <param name="name">属性名</param>
        /// <returns>値（無ければ空）</returns>
        private static string Attr(
            XmlDocument doc, XmlNamespaceManager ns, string xpath, string name)
        {
            XmlNode node = doc.SelectSingleNode(xpath, ns);

            if (node == null || node.Attributes == null || node.Attributes[name] == null)
            {
                return "";
            }

            return node.Attributes[name].Value;
        }

        /// <summary>XPath で要素の値を読む</summary>
        /// <param name="doc">XmlDocument</param>
        /// <param name="ns">XmlNamespaceManager</param>
        /// <param name="xpath">XPath</param>
        /// <returns>値（無ければ空）</returns>
        private static string Text(XmlDocument doc, XmlNamespaceManager ns, string xpath)
        {
            XmlNode node = doc.SelectSingleNode(xpath, ns);
            return (node == null) ? "" : node.InnerText;
        }

        #endregion
    }

    /// <summary>SAML2 の応答から読んだ値（#275）</summary>
    /// <remarks>**NameID は利用者を指す値**なので、**報告に出すときは扱いに注意する。**</remarks>
    public sealed class Saml2Response
    {
        /// <summary>応答の XML</summary>
        public string Xml { get; set; }

        /// <summary>StatusCode（urn の全体）</summary>
        public string StatusCode { get; set; }

        /// <summary>Destination（応答の宛先）</summary>
        public string Destination { get; set; }

        /// <summary>InResponseTo（要求の ID）</summary>
        public string InResponseTo { get; set; }

        /// <summary>Issuer</summary>
        public string Issuer { get; set; }

        /// <summary>NameID</summary>
        public string NameId { get; set; }

        /// <summary>NameID の Format</summary>
        public string NameIdFormat { get; set; }

        /// <summary>Audience</summary>
        public string Audience { get; set; }

        /// <summary>Recipient（SubjectConfirmationData）</summary>
        public string Recipient { get; set; }

        /// <summary>NotOnOrAfter（Conditions）</summary>
        public string NotOnOrAfter { get; set; }

        /// <summary>Assertion を含むか</summary>
        public bool HasAssertion { get; set; }

        /// <summary>XML の中に署名（SignatureValue）があるか</summary>
        public bool HasSignature { get; set; }

        /// <summary>アサーションの属性（#286 の段階 4。鍵は `Name`。無ければ空）</summary>
        public Dictionary<string, string> Attributes { get; set; }

        /// <summary>属性を 1 つ読む（無ければ空）</summary>
        /// <param name="name">属性の `Name`</param>
        /// <returns>値</returns>
        public string Attribute(string name)
        {
            if (this.Attributes == null)
            {
                return "";
            }

            string value = "";

            return this.Attributes.TryGetValue(name, out value) ? value : "";
        }

        /// <summary>成功の応答か</summary>
        public bool IsSuccess
        {
            get { return this.StatusCode == Saml2.StatusSuccess; }
        }

        /// <summary>診断用の 1 行（**NameID は出さない**）</summary>
        /// <returns>string</returns>
        public override string ToString()
        {
            return "StatusCode=" + (string.IsNullOrEmpty(this.StatusCode) ? "(無し)" : this.StatusCode)
                + " / Destination=" + (string.IsNullOrEmpty(this.Destination) ? "(無し)" : this.Destination)
                + " / Assertion=" + (this.HasAssertion ? "有り" : "無し");
        }
    }
}
