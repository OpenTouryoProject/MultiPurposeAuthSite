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
//* クラス名        ：ClientDisplay
//* クラス日本語名  ：承認の画面に出すクライアントの情報（画面に出す名前・logo_uri・policy_uri・tos_uri）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/24  玄人 幸道         新規（#427）
//*  2026/11/24  玄人 幸道         画面に出す名前（client_display_name・ClientDisplayName）を出すようにした（#430）
//**********************************************************************************

using System;

using MultiPurposeAuthSite.Co;

using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>
    /// **承認の画面（同意・サインイン）に出す、クライアントの情報**（#427）。
    /// </summary>
    /// <remarks>
    /// **OIDC Registration 1.0 §2**：`logo_uri` は「承認の間に利用者へ出すべき（SHOULD）」画像、`policy_uri`・`tos_uri` は「与えられたら利用者へ出すべき（SHOULD）」URL。
    ///
    /// **名前は、画面に出す名前（`client_display_name`・`ClientDisplayName`。#430）だけを出す。** **識別の名前（`ClientName`）は出さない** —
    /// **動的登録・管理画面の登録の `ClientName` は、登録した利用者の利用者名**で、出すと、登録者の利用者名をサインインする誰にでも見せる（#427）。
    /// **構成ファイルの `client_name` は内部の名前**（自己テスト・E2E が引く名前）。**画面に出す名前が無ければ、名前を出さない。**
    ///
    /// **URL は、https の絶対 URI だけを出す**（それ以外は出さずに捨てる）。
    /// **登録（動的登録・管理画面・構成ファイル）では、絶対 URI であることしか確かめていない**ので、
    /// `javascript:` などをリンクや画像に入れないよう、**出す側で絞る**（#427 で決めた。登録の振る舞いは変えない）。
    /// **値のエスケープはビュー（Razor）に任せる。**
    ///
    /// **画像は利用者のブラウザが取りに行く**（OP の外への要求にはならない。`OutboundUrlPolicy` の対象外）。
    /// </remarks>
    public sealed class ClientDisplay
    {
        /// <summary>画面に出す名前（OIDC Registration 1.0 §2 の client_name。#430。無ければ null）</summary>
        public string Name { get; private set; }

        /// <summary>logo_uri（https の絶対 URI でなければ null）</summary>
        public string LogoUri { get; private set; }

        /// <summary>policy_uri（https の絶対 URI でなければ null）</summary>
        public string PolicyUri { get; private set; }

        /// <summary>tos_uri（https の絶対 URI でなければ null）</summary>
        public string TosUri { get; private set; }

        /// <summary>constructor</summary>
        private ClientDisplay() { }

        /// <summary>client_id から、出す情報を作る</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>出す情報（**登録が無ければ null**）</returns>
        public static ClientDisplay For(string client_id)
        {
            if (string.IsNullOrEmpty(client_id)
                || string.IsNullOrEmpty(Helper.GetInstance().GetClientMode(client_id)))
            {
                //  **登録の無い client_id では出さない**（client_mode は、どの登録にも在る項目）。
                return null;
            }

            Helper helper = Helper.GetInstance();

            ClientDisplay ret = new ClientDisplay()
            {
                Name = ClientDisplay.Displayable(helper.GetClientDisplayName(client_id)),
                LogoUri = ClientDisplay.HttpsOnly(helper.GetClientLogoUri(client_id)),
                PolicyUri = ClientDisplay.HttpsOnly(helper.GetClientPolicyUri(client_id)),
                TosUri = ClientDisplay.HttpsOnly(helper.GetClientTosUri(client_id))
            };

            //  **出すものが何も無ければ出さない**（空の枠を出さない。別モデルのレビューの指摘）。
            if (ret.Name == null && ret.LogoUri == null && ret.PolicyUri == null && ret.TosUri == null)
            {
                return null;
            }

            return ret;
        }

        /// <summary>サインインの画面の ReturnUrl から、出す情報を作る</summary>
        /// <param name="returnUrl">ReturnUrl（クエリから 1 段デコードしたもの）</param>
        /// <returns>出す情報（**認可の口への戻りでなければ、または登録が無ければ null**）</returns>
        /// <remarks>
        /// **認可の口（`OAuth2AuthorizeEndpoint`）へ戻るときだけ**出す（認可の要求から来たサインイン）。
        /// **`client_id` の値は、もう 1 段エンコードされている**ので戻す（`login_hint` と同じ。`AccountController.Login`）。
        /// **PAR の要求も、クエリに `client_id` を持つ**（RFC 9126 §4）。
        /// **ReturnUrl は外から好きな値を入れられる。** 引けない値（列の幅を超える・NUL 文字）は、
        /// DB を引く前に「無い」になる（`Saml2OAuth2DataProvider.Get` の `CmnStore.IsSearchable`。#331）ので、サインインの画面は 500 にならない。
        /// </remarks>
        public static ClientDisplay FromReturnUrl(string returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl))
            {
                return null;
            }

            //  **同じサイトの相対パスだけを見る**（`/` で始まり、`//` で始まらない）。
            //    **ほかのホストの URL を ReturnUrl に入れて、このサイトのサインインの画面にクライアントの表示を出させない**（別モデルのレビューの指摘）。
            if (!returnUrl.StartsWith("/", StringComparison.Ordinal)
                || returnUrl.StartsWith("//", StringComparison.Ordinal)
                || returnUrl.StartsWith("/\\", StringComparison.Ordinal))
            {
                return null;
            }

            int query = returnUrl.IndexOf('?');
            string path = (query < 0) ? returnUrl : returnUrl.Substring(0, query);

            if (query < 0
                || !path.EndsWith(Config.OAuth2AuthorizeEndpoint, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            string client_id = CustomEncode.UrlDecode(
                UriOperator.GetParameterFromQueryString("client_id", returnUrl) ?? "");

            return ClientDisplay.For(client_id);
        }

        /// <summary>画面に出してよい名前にする（前後の空白を除き、空・見えない文字を含むなら null）</summary>
        /// <param name="value">登録された名前</param>
        /// <returns>出してよい名前（出さないなら null）</returns>
        /// <remarks>
        /// **入口（動的登録・管理画面・構成ファイル）によらず、出す側で絞る**（#430 の別モデルのレビューの指摘）。
        /// **動的登録は、見えない文字を含む名前を `invalid_client_metadata` で断る**（`ClientRegistrationProvider`）が、
        /// **管理画面と構成ファイルは確かめていない**ので、**出すときに、見えない文字を含む名前は出さない**。
        /// </remarks>
        private static string Displayable(string value)
        {
            string trimmed = (value ?? "").Trim();

            return (trimmed.Length == 0 || ClientDisplay.HasInvisibleCharacter(trimmed)) ? null : trimmed;
        }

        /// <summary>表示を偽れる、見えない文字を含むか（#430）</summary>
        /// <param name="value">値</param>
        /// <returns>含めば true</returns>
        /// <remarks>
        /// **Unicode の一般カテゴリで見る。**
        ///
        /// | カテゴリ | 例 | なぜ断るか |
        /// |---|---|---|
        /// | Cc（制御文字） | 改行・タブ | 表示を崩す |
        /// | Cf（書式文字） | 双方向の制御文字（U+202A〜U+202E・U+2066〜U+2069・U+200E・U+200F・U+061C）、幅ゼロの文字（U+200B〜U+200D）、U+FEFF、ソフト ハイフン（U+00AD） | **向きを変えたり、見えない文字を挟んだりして、別の名前に見せられる**（Unicode TR #9・UTS #39） |
        /// | Zl・Zp（行・段落の区切り） | U+2028・U+2029 | 改行と同じく表示を崩す |
        /// </remarks>
        public static bool HasInvisibleCharacter(string value)
        {
            foreach (char c in value ?? "")
            {
                System.Globalization.UnicodeCategory category = char.GetUnicodeCategory(c);

                if (category == System.Globalization.UnicodeCategory.Control
                    || category == System.Globalization.UnicodeCategory.Format
                    || category == System.Globalization.UnicodeCategory.LineSeparator
                    || category == System.Globalization.UnicodeCategory.ParagraphSeparator)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>https の絶対 URI だけを通す</summary>
        /// <param name="value">登録された値</param>
        /// <returns>https の絶対 URI なら、その URI（正規化した形）。でなければ null</returns>
        /// <remarks>
        /// **利用者情報（`user:pw@`）を持つ URI も通さない**（`https://見せたいホスト@本当のホスト/` の形で、行き先を取り違えさせない。
        /// 秘密を画面に出さない。別モデルのレビューの指摘）。**スキーム相対（`//host`）は絶対 URI でないので通さない。**
        /// </remarks>
        public static string HttpsOnly(string value)
        {
            if (string.IsNullOrEmpty(value)
                || !Uri.TryCreate(value.Trim(), UriKind.Absolute, out Uri uri)
                || uri.Scheme != Uri.UriSchemeHttps
                || !string.IsNullOrEmpty(uri.UserInfo))
            {
                return null;
            }

            return uri.AbsoluteUri;
        }
    }
}
