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
//* クラス名        ：ClientRegistrationProvider
//* クラス日本語名  ：動的クライアント登録（RFC 7591）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/18  玄人 幸道         新規（#307 の段階 1）
//*  2026/10/21  玄人 幸道         jwks_uri を受け付ける（#309 の段階 1）
//*  2026/10/21  玄人 幸道         backchannel_logout_uri は動的登録で変えさせない（#310 の段階 2）
//*  2026/10/21  玄人 幸道         frontchannel_logout_uri も動的登録で変えさせない（#310 の段階 3）
//*  2026/10/25  玄人 幸道         auth も動的登録で付けさせない（#294）
//*  2026/10/26  玄人 幸道         PUT は現行の行を土台にし、動的登録が持つ列だけを置き換えるようにした（所有者が消えていた。#294）
//*  2026/10/26  玄人 幸道         DELETE で、所有者だけでなく全利用者の同意を消すようにした（#294）
//**********************************************************************************

/*
 * 本Providerは、RFC 7591 の登録（POST）と、RFC 7592 の管理（GET / PUT / DELETE）を行う。
 * 登録は Saml2OAuth2Data の 1 行で、主キーは client_id（登録の度に新しく作る）。
 * 登録には client_registration scope のアクセス トークンが要り、所有者（OwnerUserId）はその sub の利用者
 * （利用者が居なければ、認証したクライアントの所有者）で、1 利用者が n 件の登録を持てる。
 * client_secret と registration_access_token は、登録の応答で 1 回だけ返す（後者はハッシュで保管）。
 * 管理は、その登録の registration_access_token でだけ行え、PUT は全置換、DELETE は全利用者の同意も消す。
 * client_registration と auth の scope は、動的登録では付けられない（管理画面で付ける）。
 *
 * | | ROPC（Resource Owner Password Credentials） | CC（Client Credentials） |
 * |---|---|---|
 * | `aud` | トークンを取った client_id | トークンを取った client_id |
 * | `sub` | 利用者の Id、または PPID | **そのClientIdのClientName** |
 * | `aud` の使い道 | **PPID を元の利用者に戻す鍵**（どのClient向けの `sub` か） | **所有者を引く相手**（このClientの所有者を、作る登録の所有者にする） |
 *
 * 段階ごとの決定と経緯（#307 / #309 / #310 など）は、root/programs/DesignNotes/ClientRegistrationProvider.md に在る。
 */

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// 動的クライアント登録（RFC 7591 の登録、RFC 7592 の管理）
    /// </summary>
    /// <remarks>
    /// **口（WebAPI）は両アプリの `OAuth2ResourceServerController` に在るが、
    /// 判定と保存は、ここ 1 か所で行う**（net48 版と net10.0 版で振る舞いを食い違わせないため）。
    ///
    /// **登録**（RFC 7591。`POST`）。
    ///
    /// | | |
    /// |---|---|
    /// | 認可 | **`Const.ScopeClientRegistration` を持つアクセス トークン**（**ROPC か CC で取る**） |
    /// | 所有者 | **トークンの `sub` の利用者**、**利用者が居なければ認証したクライアントの所有者**（**1 利用者が n 件持てる**） |
    /// | 器 | **既存の `Saml2OAuth2Data`**（`Saml2OAuth2DataProvider`） |
    ///
    /// **管理**（RFC 7592。`registration_client_uri` ＝ `…/register/{client_id}`）。
    ///
    /// | | |
    /// |---|---|
    /// | 認可 | **`registration_access_token`**（**登録の応答で 1 回だけ返す**。**その 1 件だけに効く**） |
    /// | `GET` | **登録を読む**（§2.1）。**`client_secret` は返さない** |
    /// | `PUT` | **全置換**（§2.2）。**`client_id` は一致必須**、**`client_secret` を入れるなら一致必須** |
    /// | `DELETE` | **消す**（§2.3）。**`204`**。**全利用者の同意も落とす** |
    ///
    /// **専用 scope のアクセス トークンでは、管理 API を叩けない** —
    /// **作る権限と、直す権限は別物**である（§2 : クライアントは
    /// `registration_access_token` を使うこと）。
    ///
    /// **クライアント認証の方法**も、API から登録できる。
    ///
    /// | | |
    /// |---|---|
    /// | `token_endpoint_auth_method` | **4 つとも登録できる**（**保管して、認証で効かせる**） |
    /// | `jwks` | **`private_key_jwt` の公開鍵**（**RSA 1 本 ＋ EC 1 本まで**） |
    /// | `tls_client_auth_subject_dn` | **mTLS の Subject DN**（RFC 8705 §2.1.2） |
    /// | `token_endpoint_auth_signing_alg` | **`client_assertion` の alg を絞る**（#262 の列） |
    ///
    /// **`client_secret` は、方法に関わらず発行する** —
    /// **デバイス フローのように、秘密しか使えない口が在る**ためである。
    /// **登録された方法は `CmnEndpoints.AllowsAuthMethod` が効かせる** —
    /// **明示が無ければ、秘密ベースの 2 つだけ**（**強い方法は明示が要る**）。
    ///
    /// **署名付きの主張**（`software_statement`）も受ける。
    ///
    /// | | |
    /// |---|---|
    /// | `software_statement` | **信頼する発行者が署名した JWT**（RFC 7591 §2.3）。**検証して、主張を本文へ重ねる** |
    /// | 優先順位 | **statement が勝つ**（§2.3 は MUST）。**食い違っても断らず、ログに残す** |
    /// | 信頼の決め | **設定の `SoftwareStatementIssuers`**（**発行者ごとに 1 件**。**クライアントごとではない**） |
    /// | `RequireSoftwareStatement` | **true なら、statement の無い登録を断る**（**`PUT` にも効く**） |
    ///
    /// **statement は、2 つの専用トークンを置き換えない。**
    /// **あれは認可、これは内容の保証**である（`SoftwareStatementProvider` の remarks）。
    /// **statement はソフトウェアに同梱されて配布される ＝ 秘密ではない**ので、
    /// **認可の代わりにはならない。**
    ///
    /// **保管しない。** **応答にも返さない**（§3.2.1 で任意）。
    ///
    /// **`jwks_uri` も受け付ける。**
    /// **要求の経路ではキャッシュを読むだけ**にし、
    /// **取りに行くのは、この口（登録のとき）と背景だけ**である —
    /// **クライアント認証の鎖が同期**で、**そこで待つと net48 で止まる**ためである。
    /// </remarks>
    public static partial class ClientRegistrationProvider
    {
        // 本体は、partial の次の 3 ファイルに在る。
        //   ClientRegistrationProvider.Crud.cs     : 前処理・登録・管理 API（public の入口）
        //   ClientRegistrationProvider.Metadata.cs : metadata の検査と、その補助（要求を読む側）
        //   ClientRegistrationProvider.Response.cs : 管理 API の部品（registration_access_token と応答を作る側）
    }
}
