# COVERAGE.md — E2E のカバレッジ

対象：E2E が叩く 2 つのサイト（net10.0 版・net48 版）と共通ライブラリ。

**`COVERAGE:BEGIN` から `COVERAGE:END` の間は手で直さない。** [`CoverageReport.ps1`](../../CoverageReport.ps1) が書く。
測り方は [`TESTING.md`](../../TESTING.md) 1 節「カバレッジを測る」。

> **カバレッジは判定に使わない。** どこを書き足すかを選ぶための指針である（[`QUALITY.md`](../../../QUALITY.md) 6 節）。
> **通ったことは、確かめたことを意味しない。** 行を通っても、結果を検証しているとは限らない。

## 更新のしかた

```powershell
cd root
.\2_RunAllTests.ps1 -Launch -Coverage
.\CoverageReport.ps1 -Update     # 全件成功した通しの結果にだけ使う
```

- **CI では測らない。** DB・コンテナが要るので、手元で測る
- **コミットするかは人が決める**

## 読み方

- **両版の和**：どちらかの版で 1 回でも通った行。`CommonLibrary` は両版が使う
- **ストアは `mem`。** `Data` の 3 方言の SQL は、この値には入らない
- **E2E で動かせない所は、測っても上がらない。** 外部のプロバイダの戻りの経路、片方の版だけの機能などである。
  下の一覧には、そうしたメソッドも含まれる
- **一覧は、単体テストを足す Issue の入力である。** 届いていないことを示すだけで、不具合を示すものではない

## 一覧の仕分け（#324。2026/11/02）

下の一覧を、どう扱うかで分けた。**DB のストア（`sql`・`ora`・`npg`）でも通しを測り、`mem` だけでは届かない分を分けた。**
DB の通しには、ストアに固有の失敗が含まれる（#327・#328。ほかに断続的な失敗。#325）ので、**下の一覧の値は、全件成功の通しではない DB の分を含まない**。

| 扱い | 対象 | 理由 |
|---|---|---|
| **DB で届いている** | `Extensions.Sts` の 40 個・230 行（`Saml2OAuth2DataProvider`・`SoftwareStatementIssuerProvider`・`DPoPProofProvider` の列の組み立て、`ConsentProvider.Value`、`SessionClientProvider.Value`、`DeviceAuthZProvider.ThrottlePolling`） | `mem` の測定に入らないだけ |
| **単体テストを足した** | `StoredCredential.FromRegistered`、`CmnDPoP.CurrentNonce`・`NonceOfSlot`・`CurrentSlot` | 外部を要らない。nonce は `-DPoPNonce` の起動でしか通らない |
| **単体テストで足す（次）** | `CmnSaml2Response.OrNone`、`Entry.JwkFromCer`・`CreateJwsFromCer`、`CmnAccessToken.SelectJwsFromCertificate` | 外部を要らない。`Entry` は証明書の用意が要る |
| **E2E で足す** | `RolesAdminController.Edit`、`ManageController.SetPassword`・`RemoveUnstructuredData`、`UsersAdminController.Details`・`List`、`HomeController` の各フロー | サイトの画面で動かせる |
| **テストしない** | 外部ログインの戻り（`ExternalLogin*`・`RemoveLogin`・`ManageLogins`）、電話番号（`AddPhoneNumber`・`VerifyPhoneNumber`・`RemovePhoneNumber`）、`IdFederationJwks`・`IdFederationSaml2Metadata` の取得 | 上流のプロバイダや SMS が要る |
| **テストしない** | `get_*` の委譲、`PingController`、`ErrorController`、`ValuesController` | 判断を持たない。外れても認証に関わらない |
| **未判断** | `WebAuthnHelper.AuthenticatorAssertion`、`DataProvider.Update`・`GetUserByCredential` | 署名の検証を通す正しいアサーションを作る足場が要る。**リスク「高」なので、優先して決める** |

<!-- COVERAGE:BEGIN -->

| 名前空間 | リスク | net10.0 版 | net48 版 | 両版の和 |
|---|---|---:|---:|---:|
| TokenProviders | 高 | 79.4%（2,532 / 3,189） | 77.9%（2,484 / 3,187） | 79.4%（2,535 / 3,192） |
| Extensions.Sts | 高 | 58.2%（2,509 / 4,308） | 58.0%（2,500 / 4,308） | 58.3%（2,510 / 4,309） |
| SamlProviders | 高 | 73.0%（214 / 293） | 73.0%（214 / 293） | 73.1%（215 / 294） |
| Controllers | 高 | 73.1%（4,384 / 5,998） | 71.3%（3,963 / 5,555） | 72.2%（8,347 / 11,553） |
| Extensions.FIDO | 高 | 52.2%（273 / 523） | — | 52.2%（273 / 523） |
| Util.Sts・Util.IdP | 中〜高 | 72.1%（1,507 / 2,089） | 70.6%（1,491 / 2,112） | 71.7%（1,533 / 2,138） |
| Password | 中〜高 | 66.0%（31 / 47） | 45.7%（32 / 70） | 45.7%（32 / 70） |
| Data | 中〜高 | 39.9%（902 / 2,259） | 39.2%（678 / 1,729） | 42.9%（1,073 / 2,499） |
| Manager・Co | 中 | 71.6%（763 / 1,066） | 73.8%（844 / 1,144） | 75.7%（887 / 1,172） |
| Network・Notifications・Entity・ViewModels・Log | 中〜低 | 63.2%（356 / 563） | 63.0%（359 / 570） | 63.1%（374 / 593） |
| その他（表に無いもの） | 中〜低 | 79.7%（467 / 586） | 87.7%（476 / 543） | 83.5%（943 / 1,129） |
| **計（Util.Test を除く）** | | 66.6%（13,938 / 20,921） | 66.8%（13,041 / 19,511） | 68.1%（18,722 / 27,472） |
| Util.Test（足場） | 低 | 88.8%（884 / 995） | 86.6%（581 / 671） | 91.0%（905 / 995） |

### リスク「高」で、どちらの版でも 1 行も通らなかったメソッド

#### TokenProviders（4 個・18 行）

| メソッド | 行 | ファイル |
|---|---:|---|
| `Entry.JwkFromCer` | 10 | `CommonLibrary/TokenProviders/SigningKeys.cs` |
| `CmnAccessToken.SelectJwsFromCertificate` | 4 | `CommonLibrary/TokenProviders/CmnAccessToken.cs` |
| `Entry.CreateJwsFromCer` | 3 | `CommonLibrary/TokenProviders/SigningKeys.cs` |
| `Entry.get_CerFilePath` | 1 | `CommonLibrary/TokenProviders/SigningKeys.cs` |

#### Extensions.Sts（28 個・239 行）

| メソッド | 行 | ファイル |
|---|---:|---|
| `Saml2OAuth2DataProvider.ToParameters` | 43 | `CommonLibrary/Extensions/Sts/Saml2OAuth2DataProvider.cs` |
| `SoftwareStatementIssuerProvider.ToParameters` | 19 | `CommonLibrary/Extensions/Sts/SoftwareStatementIssuerProvider.cs` |
| `Saml2OAuth2DataProvider.SetList` | 17 | `CommonLibrary/Extensions/Sts/Saml2OAuth2DataProvider.cs` |
| `SoftwareStatementIssuerProvider.SetList` | 17 | `CommonLibrary/Extensions/Sts/SoftwareStatementIssuerProvider.cs` |
| `DPoPProofProvider.Exists` | 11 | `CommonLibrary/Extensions/Sts/DPoPProofProvider.cs` |
| `SoftwareStatementIssuerProvider.ColumnList` | 10 | `CommonLibrary/Extensions/Sts/SoftwareStatementIssuerProvider.cs` |
| `SoftwareStatementIssuerProvider.InsertColumnList` | 9 | `CommonLibrary/Extensions/Sts/SoftwareStatementIssuerProvider.cs` |
| `CmnDPoP.NonceOfSlot` | 7 | `CommonLibrary/Extensions/Sts/CmnDPoP.cs` |
| `DPoPProofProvider.CreatedDateColumn` | 7 | `CommonLibrary/Extensions/Sts/DPoPProofProvider.cs` |
| `DPoPProofProvider.ProofIdColumn` | 7 | `CommonLibrary/Extensions/Sts/DPoPProofProvider.cs` |
| `DPoPProofProvider.TableName` | 7 | `CommonLibrary/Extensions/Sts/DPoPProofProvider.cs` |
| `Saml2OAuth2DataProvider.ColumnList` | 7 | `CommonLibrary/Extensions/Sts/Saml2OAuth2DataProvider.cs` |
| `ConsentProvider.Value` | 6 | `CommonLibrary/Extensions/Sts/ConsentProvider.cs` |
| `Saml2OAuth2DataProvider.OrderByClientID` | 6 | `CommonLibrary/Extensions/Sts/Saml2OAuth2DataProvider.cs` |
| `Saml2OAuth2DataProvider.TableName` | 6 | `CommonLibrary/Extensions/Sts/Saml2OAuth2DataProvider.cs` |
| `Saml2OAuth2DataProvider.WhereClientID` | 6 | `CommonLibrary/Extensions/Sts/Saml2OAuth2DataProvider.cs` |
| `Saml2OAuth2DataProvider.WhereOwnerUserId` | 6 | `CommonLibrary/Extensions/Sts/Saml2OAuth2DataProvider.cs` |
| `SessionClientProvider.Value` | 6 | `CommonLibrary/Extensions/Sts/SessionClientProvider.cs` |
| `SoftwareStatementIssuerProvider.TableName` | 6 | `CommonLibrary/Extensions/Sts/SoftwareStatementIssuerProvider.cs` |
| `SoftwareStatementIssuerProvider.WhereIssuerKey` | 6 | `CommonLibrary/Extensions/Sts/SoftwareStatementIssuerProvider.cs` |
| `CmnDPoP.CurrentSlot` | 4 | `CommonLibrary/Extensions/Sts/CmnDPoP.cs` |
| `DPoPProofProvider.ColumnList` | 4 | `CommonLibrary/Extensions/Sts/DPoPProofProvider.cs` |
| `DPoPProofProvider.ParameterList` | 4 | `CommonLibrary/Extensions/Sts/DPoPProofProvider.cs` |
| `DeviceAuthZProvider.ThrottlePolling` | 4 | `CommonLibrary/Extensions/Sts/DeviceAuthZProvider.cs` |
| `Saml2OAuth2DataProvider.ParameterList` | 4 | `CommonLibrary/Extensions/Sts/Saml2OAuth2DataProvider.cs` |
| `SoftwareStatementIssuerProvider.ParameterList` | 4 | `CommonLibrary/Extensions/Sts/SoftwareStatementIssuerProvider.cs` |
| `CmnDPoP.CurrentNonce` | 3 | `CommonLibrary/Extensions/Sts/CmnDPoP.cs` |
| `DPoPProofProvider.Prefix` | 3 | `CommonLibrary/Extensions/Sts/DPoPProofProvider.cs` |

#### SamlProviders（2 個・19 行）

| メソッド | 行 | ファイル |
|---|---:|---|
| `IdFederationSaml2Metadata.GetSigningKeyAsync` | 16 | `CommonLibrary/SamlProviders/IdFederationSaml2Metadata.cs` |
| `CmnSaml2Response.OrNone` | 3 | `CommonLibrary/SamlProviders/CmnSaml2Response.cs` |

#### Controllers（97 個・1359 行）

| メソッド | 行 | ファイル |
|---|---:|---|
| `ManageController.ExternalLoginCallback` | 74 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.ExternalLogin.cs` |
| `ManageController.ExternalLoginCallback` | 71 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.ExternalLogin.cs` |
| `ErrorController.Index` | 70 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ErrorController.cs` |
| `ManageController.AddPhoneNumber` | 50 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.TwoFactor.cs` |
| `ManageController.EmailConfirmation` | 47 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.Account.cs` |
| `ManageController.EmailConfirmation` | 47 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.Account.cs` |
| `ManageController.RemoveLogin` | 46 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.ExternalLogin.cs` |
| `ManageController.RemoveLogin` | 45 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.ExternalLogin.cs` |
| `ManageController.AddPhoneNumber` | 44 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.TwoFactor.cs` |
| `ManageController.ManageLogins` | 37 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.ExternalLogin.cs` |
| `ManageController.ManageLogins` | 37 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.ExternalLogin.cs` |
| `ManageController.VerifyPhoneNumber` | 33 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.TwoFactor.cs` |
| `ManageController.VerifyPhoneNumber` | 32 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.TwoFactor.cs` |
| `ManageController.SetPassword` | 29 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.Account.cs` |
| `ManageController.SetPassword` | 29 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.Account.cs` |
| `RolesAdminController.Edit` | 28 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/RolesAdminController.cs` |
| `RolesAdminController.Edit` | 28 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/RolesAdminController.cs` |
| `ManageController.RemovePhoneNumber` | 23 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.TwoFactor.cs` |
| `ErrorController.Index` | 23 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ErrorController.cs` |
| `ManageController.RemovePhoneNumber` | 23 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.TwoFactor.cs` |
| `ManageController.RemoveUnstructuredData` | 21 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.Data.cs` |
| `ManageController.RemoveUnstructuredData` | 21 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.Data.cs` |
| `ManageController.ExternalLogin` | 17 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.ExternalLogin.cs` |
| `OAuth2ResourceServerController.TestHybridFlow` | 16 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/OAuth2ResourceServerController.cs` |
| `OAuth2ResourceServerController.TestHybridFlow` | 16 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/OAuth2ResourceServerController.cs` |
| `ManageController.ExternalLogin` | 15 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.ExternalLogin.cs` |
| `ManageController.SendChangeCompletedEmail` | 15 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.Helper.cs` |
| `ManageController.SendChangeCompletedEmail` | 15 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.Helper.cs` |
| `ManageController.ManageTwoFactorAuthenticator` | 15 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.TwoFactor.cs` |
| `HomeController.PKCE_Plain` | 12 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.OAuth2.cs` |
| `HomeController.PKCE_Plain` | 12 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.OAuth2.cs` |
| `ManageController.ReplaceClaimAsync` | 11 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.Helper.cs` |
| `ManageController.ReplaceClaimAsync` | 11 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.Helper.cs` |
| `HomeController.ClientCredentialsFlow` | 10 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.Another.cs` |
| `HomeController.JWTBearerTokenFlow` | 10 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.Another.cs` |
| `HomeController.AssembleFAPI1Starter` | 10 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.Fapi.cs` |
| `HomeController.ClientCredentialsFlow` | 10 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.Another.cs` |
| `HomeController.JWTBearerTokenFlow` | 10 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.Another.cs` |
| `HomeController.AssembleFAPI1Starter` | 10 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.Fapi.cs` |
| `AccountController.LogExternalLoginClaimsMissing` | 9 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/AccountController.ExternalLogin.cs` |
| `AccountController.LogExternalLoginClaimsMissing` | 9 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/AccountController.ExternalLogin.cs` |
| `HomeController.AuthorizationCodeFAPI1` | 7 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.Fapi.cs` |
| `HomeController.AuthorizationCodeFAPI1_OIDC` | 7 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.Fapi.cs` |
| `HomeController.Hybrid_OIDC1` | 7 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.OAuth2.cs` |
| `HomeController.Hybrid_OIDC2` | 7 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.OAuth2.cs` |
| `HomeController.Hybrid_OIDC3` | 7 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.OAuth2.cs` |
| `HomeController.Implicit` | 7 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.OAuth2.cs` |
| `HomeController.Implicit_OIDC1` | 7 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.OAuth2.cs` |
| `HomeController.Implicit_OIDC2` | 7 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.OAuth2.cs` |
| `HomeController.AuthorizationCodeFAPI1` | 7 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.Fapi.cs` |
| `HomeController.AuthorizationCodeFAPI1_OIDC` | 7 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.Fapi.cs` |
| `HomeController.Hybrid_OIDC1` | 7 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.OAuth2.cs` |
| `HomeController.Hybrid_OIDC2` | 7 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.OAuth2.cs` |
| `HomeController.Hybrid_OIDC3` | 7 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.OAuth2.cs` |
| `HomeController.Implicit` | 7 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.OAuth2.cs` |
| `HomeController.Implicit_OIDC1` | 7 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.OAuth2.cs` |
| `HomeController.Implicit_OIDC2` | 7 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.OAuth2.cs` |
| `UsersAdminController.List` | 7 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/UsersAdminController.cs` |
| `AccountController.ExternalSignInFailed` | 6 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/AccountController.ExternalLogin.cs` |
| `AccountController.LogExternalLoginUserFailed` | 6 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/AccountController.ExternalLogin.cs` |
| `ManageController.AddErrors` | 6 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.Helper.cs` |
| `UsersAdminController.Details` | 6 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/UsersAdminController.cs` |
| `UsersAdminController.List` | 6 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/UsersAdminController.cs` |
| `AccountController.ExternalSignInFailed` | 6 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/AccountController.ExternalLogin.cs` |
| `AccountController.LogExternalLoginUserFailed` | 6 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/AccountController.ExternalLogin.cs` |
| `ManageController.AddErrors` | 6 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.Helper.cs` |
| `UsersAdminController.Details` | 6 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/UsersAdminController.cs` |
| `ValuesController.Get` | 6 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ValuesController.cs` |
| `PositionData..ctor` | 5 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ErrorController.cs` |
| `ManageController.get_SessionCookieName` | 4 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.cs` |
| `AccountController.SendRegisterCompletedEmail` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/AccountController.Helper.cs` |
| `PositionData.get_key` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ErrorController.cs` |
| `PositionData.get_value` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ErrorController.cs` |
| `HomeController.Index` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.cs` |
| `HomeController.Scroll` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.cs` |
| `HomeController.get_AuthenticationManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.cs` |
| `HomeController.get_RoleManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.cs` |
| `HomeController.get_SignInManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/HomeController.cs` |
| `ManageController.get_RoleManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ManageController.cs` |
| `OAuth2EndpointController.get_RoleManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/OAuth2EndpointController.cs` |
| `OAuth2ResourceServerController.get_RoleManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/OAuth2ResourceServerController.cs` |
| `OAuth2ResourceServerController.get_UserManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/OAuth2ResourceServerController.cs` |
| `PingController.Index` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/PingController.cs` |
| `RolesAdminController.get_AuthenticationManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/RolesAdminController.cs` |
| `RolesAdminController.get_SignInManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/RolesAdminController.cs` |
| `UsersAdminController.get_AuthenticationManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/UsersAdminController.cs` |
| `UsersAdminController.get_SignInManager` | 3 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/UsersAdminController.cs` |
| `AccountController.SendRegisterCompletedEmail` | 3 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/AccountController.Helper.cs` |
| `AccountController.get_SmsSender` | 3 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/AccountController.cs` |
| `HomeController.Scroll` | 3 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/HomeController.cs` |
| `ManageController.get_RoleManager` | 3 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.cs` |
| `ManageController.get_SmsSender` | 3 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/ManageController.cs` |
| `OAuth2EndpointController.get_RoleManager` | 3 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/OAuth2EndpointController.cs` |
| `OAuth2ResourceServerController.get_RoleManager` | 3 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/OAuth2ResourceServerController.cs` |
| `OAuth2ResourceServerController.get_UserManager` | 3 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/OAuth2ResourceServerController.cs` |
| `PingController.Index` | 3 | `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/Controllers/PingController.cs` |
| `ErrorController..ctor` | 2 | `MultiPurposeAuthSite/MultiPurposeAuthSite/Controllers/ErrorController.cs` |

#### Extensions.FIDO（4 個・97 行）

| メソッド | 行 | ファイル |
|---|---:|---|
| `DataProvider.Update` | 28 | `CommonLibrary/Extensions/FIDO/DataProvider.cs` |
| `WebAuthnHelper.AuthenticatorAssertion` | 28 | `CommonLibrary/Extensions/FIDO/WebAuthnHelper.cs` |
| `StoredCredential.FromRegistered` | 24 | `CommonLibrary/Extensions/FIDO/StoredCredential.cs` |
| `DataProvider.GetUserByCredential` | 17 | `CommonLibrary/Extensions/FIDO/DataProvider.cs` |


<!-- COVERAGE:END -->
