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
//* クラス名        ：WebAuthnHelper
//* クラス日本語名  ：WebAuthnHelper（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/07  西野 大介         新規
//*  2026/10/07  玄人 幸道         fido2-net-lib 4.2.0 に合わせて作り直した（#137）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

using System;
using System.Text;
using System.Collections.Generic;
using System.Threading.Tasks;

using Newtonsoft.Json.Linq;

using Fido2NetLib;
using Fido2NetLib.Objects;

namespace MultiPurposeAuthSite.Extensions.FIDO
{
    /// <summary>
    /// WebAuthnHelper（ライブラリ）
    /// https://github.com/passwordless-lib/fido2-net-lib
    /// </summary>
    //  **fido2-net-lib 4.2.0 に合わせて作り直した**（#137）。
    //    **1.0.1 からの差は「更新」では済まない。**
    //    - 要求の組み立てが**引数オブジェクト**になった（`RequestNewCredentialParams` ほか）
    //    - 戻り値が `CredentialMakeResult` / `AssertionVerificationResult` から
    //      **`RegisteredPublicKeyCredential` / `VerifyAssertionResult`** になった
    //    - **`Status` / `ErrorMessage` を持たなくなった**（成功は「例外が出ないこと」で表す）
    //    - **`Fido2NetLib.Development` が消えた**（`StoredCredential` は自前に移した）
    //    - 直列化が Newtonsoft から **System.Text.Json** になった
    //
    //    **net48 版には入れていない。** **`Fido2` は 2.0.2 を最後に `netstandard2.0` を
    //    落としている**（3.0 以降は `net6.0` / `net8.0` / `net10.0`）。
    //    **他の WebAuthn ライブラリも同様**なので、**net48 では現行版を支えられない。**
    public class WebAuthnHelper
    {
        #region mem & prop & constructor

        #region mem & prop

        /// <summary>
        /// Origin of the website: "https://host[:port]"
        /// </summary>
        private readonly string _origin;

        /// <summary>
        /// fido2-net-lib
        /// </summary>
        private readonly Fido2 _lib;

        #endregion

        #region constructor

        /// <summary>constructor</summary>
        public WebAuthnHelper()
        {
            Uri uri = new Uri(Config.OAuth2AuthorizationServerEndpointsRootURI);

            // "https://host[:port]" まで。**パスは入れない**（Origin の定義）。
            this._origin = uri.GetLeftPart(UriPartial.Authority);

            this._lib = new Fido2(new Fido2Configuration
            {
                // **`ServerDomain` / `ServerName` は obsolete** になったので
                // **`RPID` / `RPName` を使う**（4.x で警告 CS0618 が出る）。
                //
                // **RPID は実効ドメイン**（`localhost` や `example.com`）。
                // **ポートは含めない。** 資格情報はこの値に紐づくので、
                // **変えると登録済みの資格情報が使えなくなる。**
                RPID = uri.Host,
                RPName = Const.WebAuthnRpName,
                // **Origin はポートまで含む**（`clientDataJSON` の origin と照合される）。
                Origins = new HashSet<string> { this._origin }
            });
        }

        #endregion

        #endregion

        #region methods

        #region 登録フロー

        /// <summary>CredentialCreationOptions</summary>
        /// <param name="username">string</param>
        /// <param name="attestation">string</param>
        /// <param name="authenticatorAttachment">string</param>
        /// <param name="residentKey">bool</param>
        /// <param name="userVerification">string</param>
        /// <returns>CredentialCreateOptions</returns>
        public CredentialCreateOptions CredentialCreationOptions(string username,
            string attestation, string authenticatorAttachment,
            bool residentKey, string userVerification)
        {
            // 1. 利用者を引く
            // https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user
            ApplicationUser _user = CmnUserStore.FindByName(username);

            if (_user == null)
                throw new Exception(string.Format("{0} is not found.", username));

            Fido2User user = new Fido2User
            {
                DisplayName = username,
                Name = username,
                Id = Encoding.UTF8.GetBytes(username)
            };

            // 2. 登録済みの資格情報（同じ認証器で二重に登録させない）
            // https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor
            List<PublicKeyCredentialDescriptor> existingPubCredDescriptor
                = DataProvider.GetCredentialsByUser(username);

            // 3. 認証器の選択条件
            // https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
            AuthenticatorSelection authenticatorSelection = new AuthenticatorSelection
            {
                // **`RequireResidentKey` は設定しない。** `ResidentKey` から導出される
                // （4.x の `ToJson` で `requireResidentKey` が付くことを実測した）。
                ResidentKey = residentKey
                    ? ResidentKeyRequirement.Required : ResidentKeyRequirement.Discouraged,
                UserVerification = WebAuthnHelper.ToUserVerification(userVerification)
            };

            // https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment
            AuthenticatorAttachment? attachment
                = WebAuthnHelper.ToAuthenticatorAttachment(authenticatorAttachment);
            if (attachment != null)
                authenticatorSelection.AuthenticatorAttachment = attachment;

            // 4. 拡張
            // **1.x で指定していた拡張のほとんどは、仕様から落ちて 4.x に無い**
            //   （`Location` / `SimpleTransactionAuthorization` /
            //     `GenericTransactionAuthorization` / `BiometricAuthenticatorPerformanceBounds`）。
            //   **残っているもののうち、この実装が使えるものだけを付ける。**
            AuthenticationExtensionsClientInputs exts = new AuthenticationExtensionsClientInputs
            {
                // https://www.w3.org/TR/webauthn-2/#sctn-supported-extensions-extension
                Extensions = true,
                // https://www.w3.org/TR/webauthn-2/#sctn-authenticator-credential-properties-extension
                CredProps = true
            };

            // 5. 要求を組み立てる
            // https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
            return this._lib.RequestNewCredential(new RequestNewCredentialParams
            {
                User = user,
                ExcludeCredentials = existingPubCredDescriptor,
                AuthenticatorSelection = authenticatorSelection,
                AttestationPreference = WebAuthnHelper.ToAttestationPreference(attestation),
                Extensions = exts
            });
        }

        /// <summary>AuthenticatorAttestation</summary>
        /// <param name="attestationResponse">AuthenticatorAttestationRawResponse</param>
        /// <param name="options">CredentialCreateOptions</param>
        /// <returns>RegisteredPublicKeyCredentialを非同期的に返す</returns>
        public async Task<RegisteredPublicKeyCredential> AuthenticatorAttestation(
            // https://www.w3.org/TR/webauthn-2/#authenticatorattestationresponse
            AuthenticatorAttestationRawResponse attestationResponse,
            // https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
            CredentialCreateOptions options)
        {
            // 1. 検証する（**失敗は Fido2VerificationException で返る**）
            RegisteredPublicKeyCredential credential =
                await this._lib.MakeNewCredentialAsync(new MakeNewCredentialParams
                {
                    AttestationResponse = attestationResponse,
                    OriginalOptions = options,
                    // **同じ credentialId が既に在ったら拒む**（§7.1 の 22）。
                    //   **1.x では true 固定だった。** 他の利用者が登録済みの
                    //   credentialId を、別の利用者に結び付けられてしまう。
                    IsCredentialIdUniqueToUserCallback = (args, cancellationToken) =>
                    {
                        StoredCredential stored = DataProvider.GetCredentialById(args.CredentialId);
                        return Task.FromResult(stored == null);
                    }
                });

            // 2. 保存する
            DataProvider.Create(StoredCredential.FromRegistered(credential));

            // 3. 返す
            return credential;
        }

        #endregion

        #region 認証フロー

        /// <summary>CredentialGetOptions</summary>
        /// <param name="username">string</param>
        /// <param name="userVerification">string</param>
        /// <returns>AssertionOptions</returns>
        public AssertionOptions CredentialGetOptions(string username, string userVerification)
        {
            // 1. 利用者を引く
            ApplicationUser _user = CmnUserStore.FindByName(username);

            if (_user == null)
                throw new Exception(string.Format("{0} is not found.", username));

            // 2. 登録済みの資格情報
            // https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor
            List<PublicKeyCredentialDescriptor> existingPubCredDescriptor
                = DataProvider.GetCredentialsByUser(username);

            // 3. 要求を組み立てる
            // https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions
            return this._lib.GetAssertionOptions(new GetAssertionOptionsParams
            {
                AllowedCredentials = existingPubCredDescriptor,
                // **1.x では Discouraged 固定で、画面の指定を捨てていた。**
                UserVerification = WebAuthnHelper.ToUserVerification(userVerification),
                Extensions = new AuthenticationExtensionsClientInputs
                {
                    Extensions = true
                }
            });
        }

        /// <summary>AuthenticatorAssertion</summary>
        /// <param name="clientResponse">AuthenticatorAssertionRawResponse</param>
        /// <param name="options">AssertionOptions</param>
        /// <returns>VerifyAssertionResultを非同期的に返す</returns>
        public async Task<VerifyAssertionResult> AuthenticatorAssertion(
            AuthenticatorAssertionRawResponse clientResponse,
            AssertionOptions options)
        {
            // 1. 保存してある資格情報を引く
            //   **`Id` は string になった**（4.x）ので、**`RawId`（byte[]）で引く。**
            StoredCredential storedCred = DataProvider.GetCredentialById(clientResponse.RawId);

            if (storedCred == null)
                throw new Exception("The credential is not found.");

            // 2. 検証する（**失敗は Fido2VerificationException で返る**）
            VerifyAssertionResult result = await this._lib.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = clientResponse,
                OriginalOptions = options,
                StoredPublicKey = storedCred.PublicKey,
                StoredSignatureCounter = storedCred.SignatureCounter,
                IsUserHandleOwnerOfCredentialIdCallback = (args, cancellationToken) =>
                {
                    // userHandle がその credentialId の持ち主かを確かめる
                    StoredCredential cred = DataProvider.GetCredentialById(args.CredentialId);

                    if (cred == null || cred.UserHandle == null || args.UserHandle == null)
                        return Task.FromResult(false);

                    return Task.FromResult(
                        Convert.ToBase64String(cred.UserHandle)
                            == Convert.ToBase64String(args.UserHandle));
                }
            });

            // 3. 署名カウンタを進める
            storedCred.SignatureCounter = result.SignCount;
            storedCred.IsBackedUp = result.IsBackedUp;
            DataProvider.Update(storedCred);

            // 4. 返す
            return result;
        }

        #endregion

        #region 画面との受け渡し

        //  **`status` / `errorMessage` の封筒は、こちら側で付ける**（#137）。
        //    **4.x の options / result は `Status` も `ErrorMessage` も持たない**
        //    （成功は「例外が出ないこと」で表す形に変わった）。
        //
        //    **画面側（`ffWebauthn.js`）は form post で値を往復させる**ので、
        //    **HTTP のステータス コードでエラーを伝える余地が無い。**
        //    **隠しフィールドに入れる JSON 自身が、成否を持つ必要がある。**

        /// <summary>成功したときの JSON（封筒を付ける）</summary>
        /// <param name="payloadJson">string（ライブラリが出した JSON）</param>
        /// <returns>string</returns>
        public static string ToOkJson(string payloadJson)
        {
            // **ライブラリの直列化をそのまま使う。**
            //   base64url の付け方などを自前で真似ると、必ずどこかでズレる。
            JObject json = string.IsNullOrEmpty(payloadJson)
                ? new JObject() : JObject.Parse(payloadJson);

            json["status"] = "ok";
            json["errorMessage"] = "";

            return json.ToString(Newtonsoft.Json.Formatting.None);
        }

        /// <summary>失敗したときの JSON</summary>
        /// <param name="e">Exception</param>
        /// <returns>string</returns>
        public static string ToErrorJson(Exception e)
        {
            JObject json = new JObject();

            json["status"] = "error";
            json["errorMessage"] = WebAuthnHelper.FormatException(e);

            return json.ToString(Newtonsoft.Json.Formatting.None);
        }

        /// <summary>FormatException</summary>
        /// <param name="e">Exception</param>
        /// <returns>string</returns>
        public static string FormatException(Exception e)
        {
            return string.Format(
                "{0}{1}",
                e.Message,
                e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
        }

        #endregion

        #region 画面の値 → 列挙型

        //  **W3C の文字列（"cross-platform" など）は、列挙型の名前と一致しない。**
        //    `Enum.Parse` では落ちるので、**対応表を書く。**

        /// <summary>attestation</summary>
        /// <param name="value">string</param>
        /// <returns>AttestationConveyancePreference</returns>
        private static AttestationConveyancePreference ToAttestationPreference(string value)
        {
            switch ((value ?? "").ToLower())
            {
                case "indirect":
                    return AttestationConveyancePreference.Indirect;
                case "direct":
                    return AttestationConveyancePreference.Direct;
                case "enterprise":
                    return AttestationConveyancePreference.Enterprise;
                default:
                    return AttestationConveyancePreference.None;
            }
        }

        /// <summary>authenticatorAttachment</summary>
        /// <param name="value">string</param>
        /// <returns>AuthenticatorAttachment?（指定なしは null）</returns>
        private static AuthenticatorAttachment? ToAuthenticatorAttachment(string value)
        {
            switch ((value ?? "").ToLower())
            {
                case "platform":
                    return AuthenticatorAttachment.Platform;
                case "cross-platform":
                    return AuthenticatorAttachment.CrossPlatform;
                default:
                    // **指定なし**（どちらの認証器でもよい）
                    return null;
            }
        }

        /// <summary>userVerification</summary>
        /// <param name="value">string</param>
        /// <returns>UserVerificationRequirement</returns>
        private static UserVerificationRequirement ToUserVerification(string value)
        {
            switch ((value ?? "").ToLower())
            {
                case "required":
                    return UserVerificationRequirement.Required;
                case "discouraged":
                    return UserVerificationRequirement.Discouraged;
                default:
                    // **既定は preferred**（W3C の既定値）
                    return UserVerificationRequirement.Preferred;
            }
        }

        #endregion

        #endregion
    }
}
