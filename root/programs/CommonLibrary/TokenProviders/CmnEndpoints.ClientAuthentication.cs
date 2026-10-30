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
//* クラス日本語名  ：CmnEndpoints（ライブラリ）の クライアント認証
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（CmnEndpoints.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         Basic の照合で失敗を数えない。JWT Bearer の alg の一覧を足し、using を整理した（#294）
//*  2026/10/29  玄人 幸道         none（パブリック）を受け、PKCE だけで引き換えられる登録を絞る。assertion の aud に issuer を受け、秘密を定数時間で比べる（#294）
//*  2026/10/30  玄人 幸道         デバイス認可のクライアント認証で client_assertion（private_key_jwt）も受ける（#294）
//*  2026/10/30  玄人 幸道         使われなくなった DeviceAuthZClientAuthentication（引数 3 つの版）を消した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints（クライアント認証）</summary>
    public partial class CmnEndpoints
    {
        #region Common

        #region Public

        #region　ClientAuthentication

        /// <summary>クライアント認証（送られてきた資格情報の種類を問わない）</summary>
        /// <param name="client_id">client_id（client_secret / mTLS のとき）</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="clientAssertion">client_assertion（private_key_jwt）</param>
        /// <param name="x509">クライアント証明書（mTLS）</param>
        /// <param name="authnedClientId">認証できたクライアントの client_id</param>
        /// <param name="proof">何を証明したか</param>
        /// <returns>認証できたか</returns>
        /// <remarks>
        /// **どの方式で来ても、ここで受ける**（#239）。
        /// 以前は `client_secret` / mTLS の版と、アサーションの版が別々で、
        /// **認可コード グラントだけがアサーションを受けていた。**
        /// `refresh_token` や `/revoke` では `private_key_jwt` が通らなかった。
        ///
        /// **アサーションのときは `client_id` をアサーションの `iss` から得る**
        /// （RFC 7523 §3 : `iss` はクライアントの識別子）。
        /// 認証の後で client_id を使う処理（トークンとの紐付け、失効）は、**こちらを使うこと。**
        ///
        /// **要否は決めない。** コンフィデンシャルかどうかは呼び出し側が判断する
        /// （RFC 6749 §3.2.1。パブリック クライアントは認証しない）。
        /// この関数は「**何を証明したか**」を返すだけで、
        /// その証明で通す登録種別は `ClientModePolicy` の表が決める（#224）。
        /// </remarks>
        public static bool ClientAuthentication(
            string client_id, string client_secret, string clientAssertion,
            ref X509Certificate2 x509, out string authnedClientId, out ClientModePolicy.Proof proof)
        {
            if (!string.IsNullOrEmpty(clientAssertion))
            {
                // private_key_jwt（client_id はアサーションから得る）
                return CmnEndpoints.ClientAuthentication(
                    clientAssertion, out authnedClientId, ref x509, out proof);
            }

            authnedClientId = client_id;

            // client_secret（basic / post）または mTLS
            return CmnEndpoints.ClientAuthentication(
                client_id, client_secret, ref x509, out proof);
        }

        #region client_id & (client_secret or x509)

        /// <summary>ClientAuthentication</summary>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="proof">何を証明したか（client_secret か mTLS か）</param>
        /// <returns>bool</returns>
        /// <remarks>
        /// **以前は水準（permittedLevel）を返していた**（client_secret なら normal、x509 なら fapi2）。
        /// いまは何を証明したかを返し、通す登録種別は ClientModePolicy の表で決める（#224）。
        /// </remarks>
        public static bool ClientAuthentication(string client_id, string client_secret,
            ref X509Certificate2 x509, out ClientModePolicy.Proof proof)
        {
            proof = ClientModePolicy.Proof.None;

            //  **続けて失敗しているクライアントは、断る**（#305 の段階 2）。
            //    **断っている間は、正しい資格情報でも通さない** — それがロックアウトである。
            //    **応答は従来と同じ `invalid_client`**（**断っていることを教えない**）。
            //
            //  **鍵は「クライアント ＋ 送信元」**（#305 の段階 4）。
            //    **断るのは、失敗を重ねた送信元だけ**である。
            string failureKey = AuthFailureProvider.ClientKey(client_id);

            if (AuthFailureProvider.IsLockedOut(failureKey))
            {
                Logging.MyOperationTrace(string.Format(
                    "The client authentication of {0} was refused. (too many failures)", client_id));

                return false;
            }

            // client_id & client_secret
            if (!string.IsNullOrEmpty(client_id))
            {
                if (!string.IsNullOrEmpty(client_secret))
                {
                    // *.config or Saml2OAuth2Dataテーブルを参照して、
                    // クライアント認証（client_secret）を行なう。
                    string registeredSecret = Helper.GetInstance().GetClientSecret(client_id);

                    //  **登録が空なら通さない**（#305 の段階 4。**空と空の一致を作らない**）。
                    //  **登録された方法でなければ通さない**（#307 の段階 3）。
                    //    **明示が無ければ、秘密ベースの 2 つを暗黙に許す。**
                    if (!string.IsNullOrEmpty(registeredSecret)
                        && CmnEndpoints.FixedTimeEquals(client_secret, registeredSecret)
                        && CmnEndpoints.AllowsAuthMethod(
                            client_id, ClientModePolicy.Proof.ClientSecret))
                    {
                        proof = ClientModePolicy.Proof.ClientSecret;
                        x509 = null; // client_secretがあった場合、x509を無効化

                        //  **成功したら、数えた分は消す**（連続した失敗だけを数える）。
                        AuthFailureProvider.Clear(failureKey);

                        return true;
                    }
                }
                else if (x509 != null)
                {
                    // *.config or Saml2OAuth2Dataテーブルを参照して、
                    // クライアント認証（X509Certificate2）を行なう。
                    string registeredDn = Helper.GetInstance().GetTlsClientAuthSubjectDn(client_id);

                    //  **登録が空なら通さない**（#305 の段階 4）。
                    //    **以前は、登録の無い `client_id` に Subject が空の証明書を出すと、
                    //    空と空が一致して通った**（`/revoke` / `/introspect` は
                    //    この後の登録種別の判定を通らないので、そこで落ちない）。
                    //  **登録された方法でなければ通さない**（#307 の段階 3）。
                    //    **`tls_client_auth` の明示が要る** — **DN を登録しただけでは通らない。**
                    if (!string.IsNullOrEmpty(registeredDn)
                        && x509.Subject == registeredDn
                        && CmnEndpoints.AllowsAuthMethod(
                            client_id, ClientModePolicy.Proof.Mtls))
                    {
                        proof = ClientModePolicy.Proof.Mtls;

                        AuthFailureProvider.Clear(failureKey);

                        return true;
                    }
                }
            }

            //  **失敗を 1 回数える**（#305 の段階 2）。
            //    **`client_id` が空のときは数えない**（鍵にならない）。
            //
            //  **登録されていない `client_id` では数えない**（#305 の段階 4）。
            //    **要求の `client_id` をそのまま鍵にして行を作ると、
            //    誰でも `AuthFailure` 表を好きなだけ太らせられる。**
            //    **登録の有無は `GetClientName` で見る**
            //    （`DeviceAuthZClientAuthentication` と同じ見方）。
            if (!string.IsNullOrEmpty(client_id)
                && !string.IsNullOrEmpty(Helper.GetInstance().GetClientName(client_id)))
            {
                AuthFailureProvider.Record(failureKey);
            }

            return false;
        }

        /// <summary>ClientAuthentication（互換の入口）</summary>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="permittedLevel">OAuth2AndOIDCEnum.ClientMode</param>
        /// <returns>bool</returns>
        /// <remarks>
        /// **水準を返す以前の形を、呼び出し元のために残してある**（両アプリの revoke / introspect）。
        /// そこでは水準を使っていない。**新しく使うときは、証明を返す版を使うこと**（#224）。
        /// </remarks>
        public static bool ClientAuthentication(string client_id, string client_secret,
            ref X509Certificate2 x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel)
        {
            bool authned = CmnEndpoints.ClientAuthentication(
                client_id, client_secret, ref x509, out ClientModePolicy.Proof proof);

            permittedLevel = (proof == ClientModePolicy.Proof.Mtls)
                ? OAuth2AndOIDCEnum.ClientMode.fapi2 : OAuth2AndOIDCEnum.ClientMode.normal;

            return authned;
        }

        #endregion

        #region Device AuthZ

        /// <summary>
        /// Device AuthZ グラントを、このクライアントに許すか（登録種別で判定する）
        /// </summary>
        /// <param name="client_id">string</param>
        /// <returns>許すなら true</returns>
        /// <remarks>
        /// **許すのは normal と device の登録だけ。**
        /// fapi1 / fapi2 / fapi_ciba の登録は、より強いクライアント認証
        /// （PKCE / private_key_jwt / mTLS など）を求めている。
        /// このグラントは client_secret だけで通るので、**使わせると、登録で求めた強さを満たさずに
        /// トークンが出てしまう。**
        ///
        /// ※ 他のグラントは CheckClientMode で登録種別を見ているが、このグラントには判定が無かった。
        ///    段階 1 で ClientModePolicy の表に取り込んだ（#224）。
        /// </remarks>
        public static bool IsDeviceAuthZAllowed(string client_id)
        {
            // **登録で許されたグラントか**（RFC 7591 §2 の `grant_types`。#307 の段階 1）。
            //   **利用者に user_code を打ち込ませる前に断る**（登録が無ければ絞らない）。
            if (!CmnEndpoints.CheckClientGrantType(client_id, ClientModePolicy.Flow.DeviceAuthZ))
            {
                return false;
            }

            // 表の「Device AuthZ → normal / device」の行で判定する（#224 の段階 1）。
            //   この行は証明を問わないので、MayUse で足りる。既知でない登録値は拒否（段階 2）。
            return ClientModePolicy.MayUse(
                Helper.GetInstance().GetClientMode(client_id), ClientModePolicy.Flow.DeviceAuthZ);
        }

        /// <summary>Device AuthZのクライアント認証（`client_assertion` も受ける。#294）</summary>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="clientAssertion">client_assertion（private_key_jwt。無ければ空）</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="authnedClientId">認証できたクライアントの client_id</param>
        /// <returns>bool</returns>
        /// <remarks>
        /// RFC 8628
        /// - 3.1 : デバイス認可要求で、クライアントを識別する。
        /// - 3.4 : トークン要求で、コンフィデンシャル クライアントは認証する。
        /// パブリック クライアント（client_secret未登録）は、client_idの確認だけを行う。
        ///
        /// **`client_assertion` が在れば、他の口と同じく `private_key_jwt` で認証する**（#294）。
        /// **client_id はアサーションの `iss` から得る**（RFC 7523 §3）。
        /// **フォームの client_id も送られていれば、食い違いを断る。**
        /// **以前は読んでおらず、`private_key_jwt` で登録したクライアントはデバイス フローを使えなかった**
        /// （動的登録は、その組み合わせを登録の時点で断っていた）。
        /// </remarks>
        public static bool DeviceAuthZClientAuthentication(
            string client_id, string client_secret, string clientAssertion,
            ref X509Certificate2 x509, out string authnedClientId)
        {
            authnedClientId = client_id;

            if (!string.IsNullOrEmpty(clientAssertion))
            {
                if (!CmnEndpoints.ClientAuthentication(
                    "", "", clientAssertion, ref x509, out authnedClientId, out ClientModePolicy.Proof _))
                {
                    return false;
                }

                return string.IsNullOrEmpty(client_id)
                    || string.Equals(client_id, authnedClientId, StringComparison.Ordinal);
            }

            // client_idは必須
            if (string.IsNullOrEmpty(client_id)) return false;

            // 未登録のclient_idは拒否
            if (string.IsNullOrEmpty(Helper.GetInstance().GetClientName(client_id))) return false;

            //  **`token_endpoint_auth_method` が `none` なら、パブリック クライアント**（RFC 7591 §2。#294）。
            //    **秘密を持っていても使えない**（`AllowsAuthMethod` が断る）ので、client_id の確認だけにする。
            if (CmnEndpoints.IsRegisteredAsPublic(client_id)) return true;

            // コンフィデンシャル クライアントは認証必須
            // - client_secretを登録済み
            // - tls_client_auth_subject_dnを登録済み（mTLSのみのクライアント）
            // - **公開鍵を登録済み**（private_key_jwt のみのクライアント）（#307 の段階 3）
            // - x509を提示してきた
            //
            //  **鍵の登録を数えていなかった**（#307 の段階 3 で閉じた）。
            //    **秘密も DN も無く、鍵だけを登録したクライアント**は、
            //    **ここで「パブリック クライアント」とみなされ、`client_id` の確認だけで通っていた。**
            //    **`IsDeviceAuthZAllowed` のコメントが警戒しているのと同じこと**が、
            //    **逆向き（強い方法を登録した側）で起きていた。**
            //
            //  **`client_assertion` で来た要求は、上で認証を済ませている**（#294）。
            //    **ここに来るのは、秘密・証明書で来た要求か、何も送らなかった要求**である。
            //    **鍵だけのクライアントが何も送らなければ、ここで認証に失敗して断られる** — **出さない側に転ぶ。**
            //  **`jwks_uri` を登録したクライアントも、コンフィデンシャルである**（#309 の段階 1）。
            //    **数えないと、鍵を URL で登録したクライアントが
            //    「パブリック」とみなされ、`client_id` の確認だけで通ってしまう**
            //    （**列の鍵を数えていなかった #307 の段階 3 と、同じ形の穴**）。
            if (!string.IsNullOrEmpty(Helper.GetInstance().GetClientSecret(client_id))
                || !string.IsNullOrEmpty(Helper.GetInstance().GetTlsClientAuthSubjectDn(client_id))
                || !string.IsNullOrEmpty(Helper.GetInstance().GetJwkRsaPublickey(client_id))
                || !string.IsNullOrEmpty(Helper.GetInstance().GetJwkECDsaPublickey(client_id))
                || !string.IsNullOrEmpty(Helper.GetInstance().GetJwksUri(client_id))
                || x509 != null)
            {
                return CmnEndpoints.ClientAuthentication(
                    client_id, client_secret, ref x509,
                    out ClientModePolicy.Proof _);
            }

            // パブリック クライアントは、client_idの確認のみ
            return true;
        }

        #endregion

        #region assertion

        /// <summary>
        /// `jwks_uri` から引いた鍵を、何本まで試すか（**`kid` の無い JWS のとき**）。
        /// </summary>
        /// <remarks>
        /// **`kid` が在れば 1 本に決まる**（RFC 7515 §4.1.4 は任意なので、無いこともある）。
        /// **無いときは在る鍵を順に試す**ことになるので、**上限を置く** —
        /// **鍵を何十本も並べた JWK Set を出す相手に、検証を何十回もさせられないため。**
        /// </remarks>
        private const int MaxJwksFromUri = 4;

        /// <summary>ClientAuthentication</summary>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="proof">何を証明したか（成功なら private_key_jwt）</param>
        /// <returns>bool</returns>
        public static bool ClientAuthentication(string assertion, out string client_id,
            ref X509Certificate2 x509, out ClientModePolicy.Proof proof)
        {
            if (!string.IsNullOrEmpty(assertion))
            {
                // assertionがあった場合、x509を無効化
                x509 = null;

                // **JWT でない値・iss の無い JWT・未登録のクライアントで、例外にしない**（#241）。
                //   ここは /token・/par・/ciba_authz・/revoke・/introspect の全てから通る（#238 / #239）。
                JObject payload = JwtReader.TryReadPayload(assertion);
                string assertionIss = (payload == null)
                    ? "" : (string)payload[OAuth2AndOIDCConst.iss];

                // pubKey
                //
                // **登録された公開鍵を、RSA → ECDSA の順に試す**（#129 の段階 2）。
                //   **以前は jwk_rsa_publickey しか渡しておらず、RS256 しか通らなかった。**
                //   `JwtAssertion.Verify` は **JWK の `kty` を見て RSA / EC を選ぶ**ので、
                //   **ECDSA の公開鍵を渡せば ES256 が通る**（框は両方に対応していた）。
                //
                // **アサーションの `alg` ヘッダでは選ばない**（C-8 と同じ轍を踏まないため）。
                //   **登録済みの鍵で順に検証する**だけなので、外から alg を選ばせていない。
                //   **どちらの鍵でも通る**が、どちらも配備者が登録した鍵である。
                //   （片方だけ登録すれば、その方式だけになる。）
                string[] pubKeys = string.IsNullOrEmpty(assertionIss)
                    ? new string[0]
                    : new string[]
                    {
                        CmnEndpoints.DecodeRegisteredJwk(
                            Helper.GetInstance().GetJwkRsaPublickey(assertionIss)),
                        CmnEndpoints.DecodeRegisteredJwk(
                            Helper.GetInstance().GetJwkECDsaPublickey(assertionIss))
                    };

                //  **`jwks_uri` が登録されているなら、その URL から引いた鍵も試す**（#309 の段階 1）。
                //
                //  **ここは同期の経路**（`/token` / `/par` / `/ciba_authz` /
                //    `/revoke` / `/introspect` の全部から `static bool` で呼ばれる）なので、
                //    **キャッシュを読むだけ**にする。**取りに行って待つと net48 で止まる**
                //    （**継続が同期コンテキストへ戻れない**。#309 の起票）。
                //
                //  **引けなければ、背景で取り直して、この 1 本は断る**（段階 1 の決め (C)(1)）。
                //    **次の試行で通る。** **理由はログに残す**（#253 の方針。**鍵は出さない**）。
                if (!string.IsNullOrEmpty(assertionIss))
                {
                    string jwksUri = Helper.GetInstance().GetJwksUri(assertionIss);

                    if (!string.IsNullOrEmpty(jwksUri))
                    {
                        string[] fromUri = RemoteJwkSetStore.PickJwksFromCache(
                            jwksUri, JwtReader.TryReadKid(assertion),
                            CmnEndpoints.MaxJwksFromUri).Select(jwk => jwk.ToString()).ToArray();

                        if (fromUri.Length == 0)
                        {
                            RemoteJwkSetStore.RefillInBackground(jwksUri);

                            Logging.MyOperationTrace(string.Format(
                                "The key of the client assertion was not in the jwks_uri cache. ({0})",
                                assertionIss));
                        }

                        pubKeys = pubKeys.Concat(fromUri).ToArray();
                    }
                }

                // **登録 token_endpoint_auth_signing_alg で絞る**（#262）。
                //   **登録が無ければ、従来どおり両方を試す**（下位互換）。
                //   **登録が在れば、その alg でなければ通さない**
                //   （鍵を両方登録したクライアントを、片方に絞れるようにするため）。
                //   **既知でない値が登録されていれば拒否する**（#224 と同じ方針）。
                if (!CmnEndpoints.AllowsVerifyingAlg(
                    Helper.GetInstance().GetTokenEndpointAuthSigningAlg(assertionIss),
                    CmnEndpoints.TokenEndpointAuthSigningAlgs,
                    JwtReader.TryReadAlg(assertion)))
                {
                    proof = ClientModePolicy.Proof.None;
                    client_id = "";
                    return false;
                }

                foreach (string pubKey in pubKeys)
                {
                    if (string.IsNullOrEmpty(pubKey))
                    {
                        // その方式の公開鍵が登録されていない
                        continue;
                    }

                    // 署名検証 ≒ クライアント認証
                    if (CmnEndpoints.TryVerifyAssertion(assertion, pubKey, out string iss))
                    {
                        // aud 検証
                        //
                        //  **登録された方法でなければ通さない**（#307 の段階 3）。
                        //    **`private_key_jwt` の明示が要る** — **鍵を登録しただけでは通らない。**
                        //    **`client_id` はアサーションの `iss`**（RFC 7523 §3）なので、それで引く。
                        //  **aud は、トークン エンドポイントの URL か、この IdP の issuer**（#294）。
                        //    RFC 7523 §3 / FAPI 2.0 Security Profile §5.3.2.1（issuer を受けること）。
                        if (CmnEndpoints.IsAssertionAudience(payload)
                            && CmnEndpoints.AllowsAuthMethod(
                                iss, ClientModePolicy.Proof.PrivateKeyJwt))
                        {
                            proof = ClientModePolicy.Proof.PrivateKeyJwt;
                            client_id = iss;
                            return true;
                        }
                    }
                }
            }

            proof = ClientModePolicy.Proof.None;
            client_id = "";
            return false;
        }

        #endregion

        #endregion

        #endregion

        #region クライアント認証の補助（AuthZ(N)Endpoint の region から移した。#294）

        #region Basic の資格情報（#237）

        /// <summary>
        /// Authorization ヘッダ（Basic）から資格情報を取り出す（#237）
        /// </summary>
        /// <param name="authHeader">Authorization ヘッダの値</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <returns>Basic の資格情報があったか</returns>
        /// <remarks>
        /// **RFC 6749 §2.3.1 は、`client_id` と `client_secret` を
        /// `application/x-www-form-urlencoded` で符号化してから Base64 にする**ことを求めている。
        /// 以前は復号しておらず、**仕様に従うクライアントは、記号を含む秘密だと認証できなかった**
        /// （`+` `/` `=` `%` `:` など。特に `:` は分割位置がずれる）。
        ///
        /// **復号後と復号前の両方を受ける。**
        /// 復号後で認証できなければ、復号前の値を返す（**符号化しないクライアントを壊さない**）。
        /// Open棟梁 の既存のクライアントは符号化しない（OpenTouryo #592 で送り側も符号化するようになったが、
        /// 配備済みのものは残る）。
        ///
        /// **英数字だけの値では、どちらも同じ文字列になる**ので、この分岐は効かない。
        ///
        /// **切り替えは Open棟梁 の `AuthenticationHeader.GetCredentials`（照合を渡す版）が行う**（#294）。
        /// ここで渡すのは**照合**で、**読むだけ**（設定・ストアの参照）なので、副作用は無い。
        /// **照合は `ClientAuthentication` を呼ばない**（#294）。
        /// **あちらは失敗を数え、成功で数えた分を消す**（#305 の段階 2）ので、
        /// **ここで呼ぶと、記号を含む値の 1 回の失敗が 2 回と数えられていた**（この後に呼び出し側がもう一度認証する）。
        /// **方法（`token_endpoint_auth_method`）とロックアウトは、その本番の認証で見る。**
        /// **フォーム（`client_secret_post`）の値は復号しない。**
        /// そちらは枠組みが既に復号しており、二重に復号すると壊れる。
        /// </remarks>
        public static bool GetBasicCredentials(
            string authHeader, out string client_id, out string client_secret)
        {
            return AuthenticationHeader.GetCredentials(authHeader,
                CmnEndpoints.MatchesClientSecret,
                out client_id, out client_secret);
        }

        /// <summary>登録された client_secret と一致するか（数えない・記録しない）</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <returns>一致すれば true</returns>
        /// <remarks>
        /// **`GetBasicCredentials` が、復号の前後のどちらを使うかを決めるためだけに使う。**
        /// **登録が空なら一致としない**（`ClientAuthentication` と同じく、空と空の一致を作らない）。
        /// </remarks>
        private static bool MatchesClientSecret(string client_id, string client_secret)
        {
            if (string.IsNullOrEmpty(client_id) || string.IsNullOrEmpty(client_secret))
            {
                return false;
            }

            string registeredSecret = Helper.GetInstance().GetClientSecret(client_id);

            return !string.IsNullOrEmpty(registeredSecret)
                && CmnEndpoints.FixedTimeEquals(client_secret, registeredSecret);
        }

        /// <summary>2 つの文字列を、一致した長さで時間が変わらないように比べる（#294）</summary>
        /// <param name="a">文字列</param>
        /// <param name="b">文字列</param>
        /// <returns>一致すれば true</returns>
        /// <remarks>
        /// **`==` は最初に食い違った所で止まる**ので、**応答の時間から一致した長さを推し量れる。**
        /// **秘密の照合には、全部を比べてから答える比較を使う**（`CryptographicOperations.FixedTimeEquals` は net48 に無い）。
        /// **長さの違いは隠さない**（秘密の長さは、それだけでは手掛かりにならない）。
        /// </remarks>
        private static bool FixedTimeEquals(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            int diff = 0;

            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }

            return diff == 0;
        }

        #endregion

        #region 検証する側の alg（#262）

        /// <summary>`client_assertion` で受ける alg（#262）</summary>
        /// <remarks>
        /// **この一覧が、広告（`token_endpoint_auth_signing_alg_values_supported`）と、
        /// 登録値の検証（`token_endpoint_auth_signing_alg`）の両方を決める。**
        ///
        /// **中身は上流の都合である。** `JwtAssertion.Verify` が
        /// **JWK の `kty` を見て `JWS_RS256_Param` / `JWS_ES256_Param` を選ぶ**ので、この 2 つになる。
        /// **広げるには上流の対応が要る**（alg を受け取るオーバーロードが無い）。
        /// </remarks>
        public static readonly string[] TokenEndpointAuthSigningAlgs = new string[]
        {
            JwtConst.RS256, JwtConst.ES256
        };

        /// <summary>JWT Bearer グラント（RFC 7523 §2.1）の `assertion` で受ける alg（#294）</summary>
        /// <remarks>
        /// **検証の鍵は登録の RSA 公開鍵だけ**（`GrantJwtBearerTokenCredentials`）なので、いまは `RS256` だけ。
        /// **`JwtAssertion.Verify` はヘッダの alg を見ない**ので、**名乗りを、ここで揃える。**
        /// </remarks>
        public static readonly string[] JwtBearerSigningAlgs = new string[]
        {
            JwtConst.RS256
        };

        /// <summary>Request Object（`/ros` / `/par` / `request`）で受ける alg（#262）</summary>
        /// <remarks>
        /// **`RequestObject.Verify` が `JWS_RS256_Param` 固定**なので、いまは `RS256` だけ。
        /// **CIBA の `request` は別**（`VerifyCiba` が `ES256` 固定。仕様でも別の登録項目）。
        /// </remarks>
        public static readonly string[] RequestObjectSigningAlgs = new string[]
        {
            JwtConst.RS256
        };

        #endregion

        #region 登録されたクライアント認証の方法（#307 の段階 3）

        /// <summary>この配備が扱う `token_endpoint_auth_method`（#307 の段階 3）</summary>
        /// <remarks>
        /// **この一覧が、広告（`token_endpoint_auth_methods_supported`）と、
        /// 登録値の検証（`AllowsAuthMethod` / 動的登録）と、画面の選択肢を決める。**
        ///
        /// **4 つとも、検証する側は実装済みである**
        /// （秘密は `ClientAuthentication`、`private_key_jwt` は #239 / #129 の段階 2、
        /// `tls_client_auth` は #226）。
        ///
        /// **`none`（パブリック クライアント。RFC 7591 §2）も受ける**（#294）。
        /// **認証しないことの明示**で、**認可コードは PKCE だけで引き換える**（`MayUsePkceOnly`）。
        /// **認証を要する口（revoke / introspect）の広告には出さない**（`AuthenticatingMethods`）。
        /// </remarks>
        public static readonly string[] TokenEndpointAuthMethods = new string[]
        {
            OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringByEmit(),
            OAuth2AndOIDCEnum.AuthMethods.client_secret_post.ToStringByEmit(),
            OAuth2AndOIDCEnum.AuthMethods.private_key_jwt.ToStringByEmit(),
            OAuth2AndOIDCEnum.AuthMethods.tls_client_auth.ToStringByEmit(),
            CmnEndpoints.TokenEndpointAuthMethodNone
        };

        /// <summary>`token_endpoint_auth_method` の `none`（パブリック クライアント。RFC 7591 §2。#294）</summary>
        public const string TokenEndpointAuthMethodNone = "none";

        /// <summary>認証する方法だけ（`none` を除く。revoke / introspect の広告。#294）</summary>
        public static string[] AuthenticatingMethods
        {
            get
            {
                return CmnEndpoints.TokenEndpointAuthMethods
                    .Where(x => x != CmnEndpoints.TokenEndpointAuthMethodNone).ToArray();
            }
        }

        /// <summary>`token_endpoint_auth_method` に `none` を登録したクライアントか（#294）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>`none` なら true</returns>
        private static bool IsRegisteredAsPublic(string client_id)
        {
            return Helper.GetInstance().GetTokenEndpointAuthMethod(client_id)
                == CmnEndpoints.TokenEndpointAuthMethodNone;
        }

        /// <summary>認可コードを、PKCE だけで（クライアント認証なしに）引き換えてよいか（C-40。#294）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>よければ true</returns>
        /// <remarks>
        /// | 登録の `token_endpoint_auth_method` | PKCE だけ |
        /// |---|---|
        /// | **`none`**（パブリックの明示） | **通す** |
        /// | **空**（明示しない） | **通す**（**従来どおり**。雛形の SPA / ネイティブは秘密を持ったまま PKCE だけで引き換えている） |
        /// | **それ以外**（認証の方法を明示した） | **通さない**（RFC 6749 §4.1.3 : コンフィデンシャル クライアントは認証する） |
        ///
        /// **空を通すのは、既定の挙動を変えないため**である。**閉じたいクライアントは、方法を明示する。**
        /// </remarks>
        private static bool MayUsePkceOnly(string client_id)
        {
            string registered = Helper.GetInstance().GetTokenEndpointAuthMethod(client_id);

            return string.IsNullOrEmpty(registered)
                || registered == CmnEndpoints.TokenEndpointAuthMethodNone;
        }

        /// <summary>assertion の aud が、この IdP を指しているか（#294）</summary>
        /// <param name="payload">assertion の payload（署名は別に確かめること）</param>
        /// <returns>指していれば true</returns>
        /// <remarks>
        /// **トークン エンドポイントの URL か、issuer**（RFC 7523 §3 / FAPI 2.0 Security Profile §5.3.2.1）。
        ///
        /// **配列の aud は受けない。** RFC 7519 §4.1.3 は配列を認めるが、
        /// **Open棟梁 の `JwtAssertion.Verify` が aud を文字列として読む**ので、配列だと検証そのものができない
        /// （`TryVerifyAssertion` が断る）。**受けるには上流の対応が要る。**
        /// </remarks>
        private static bool IsAssertionAudience(JObject payload)
        {
            string aud = CmnEndpoints.StringClaimOf(payload, OAuth2AndOIDCConst.aud);

            return !string.IsNullOrEmpty(aud)
                && (aud == Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint
                    || aud == CmnServerParams.IssuerId);
        }

        /// <summary>assertion の署名と期限を検証する（読めない形なら false。#294）</summary>
        /// <param name="assertion">assertion（JWT）</param>
        /// <param name="pubKey">公開鍵（JWK）</param>
        /// <param name="iss">iss</param>
        /// <returns>検証できれば true</returns>
        /// <remarks>
        /// **`JwtAssertion.Verify`（Open棟梁）は、`aud` などを文字列として読み、配列だと例外を投げる。**
        /// **外から来た値なので、例外にしない**（#241 と同じ方針）。**以前は HTTP 500 だった。**
        /// </remarks>
        private static bool TryVerifyAssertion(string assertion, string pubKey, out string iss)
        {
            try
            {
                return JwtAssertion.Verify(
                    assertion, out iss, out string _, out string _, out JObject _, pubKey);
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The assertion could not be verified. ({0})", ex.GetType().Name));

                iss = "";
                return false;
            }
        }

        /// <summary>この証明で、このクライアントを通してよいか（#307 の段階 3）</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="proof">実際に示された証明</param>
        /// <returns>通してよければ true</returns>
        /// <remarks>
        /// **登録された `token_endpoint_auth_method` と、実際の証明を突き合わせる。**
        ///
        /// | 登録 | 通す証明 |
        /// |---|---|
        /// | **空**（未登録） | **`ClientSecret` だけ**（＝ `client_secret_basic` / `client_secret_post` を暗黙に許す） |
        /// | `client_secret_basic` / `client_secret_post` | **`ClientSecret`** |
        /// | **`private_key_jwt`** | **`PrivateKeyJwt`** |
        /// | **`tls_client_auth`** | **`Mtls`** |
        /// | **`none`** | **通さない**（パブリック クライアント。#294） |
        /// | **既知でない値** | **通さない**（登録の誤り。#224 の段階 2 と同じ方針） |
        ///
        /// **つまり「強い方法は明示が要る」。** **鍵や DN を登録しただけでは、その方法では通らない。**
        /// **以前は「登録されている資格のどれかで通る」**作りだったため、
        /// **登録で求めた強さが効かなかった。**
        ///
        /// **`client_secret_basic` と `client_secret_post` は区別しない。**
        /// **どちらで来たかを、この層は知らない**（口が `client_id` ＋ `client_secret` に
        /// 正規化して渡す）。**どちらを登録しても、両方が通る。**
        ///
        /// **断ったときは、運用のログに残す** — **資格情報は合っていたのに通らない**ので、
        /// **残さないと配備側で原因が分からない。** **秘密そのものは書かない。**
        ///
        /// **呼ぶのは「資格情報が合った後」である。** 失敗の数え（#305 の段階 2）は
        /// 従来どおり呼び出し側で行われる（**方法の違いも、認証の失敗として数える**）。
        /// </remarks>
        private static bool AllowsAuthMethod(string client_id, ClientModePolicy.Proof proof)
        {
            string registered = Helper.GetInstance().GetTokenEndpointAuthMethod(client_id);

            bool allowed;

            if (string.IsNullOrEmpty(registered))
            {
                // **明示が無ければ、秘密ベースの 2 つだけ**（#307 の段階 3 の決定）。
                allowed = (proof == ClientModePolicy.Proof.ClientSecret);
            }
            else if (Array.IndexOf(CmnEndpoints.TokenEndpointAuthMethods, registered) < 0)
            {
                // **既知でない値が登録されている**（設定の誤り）。
                allowed = false;
            }
            else if (registered == CmnEndpoints.TokenEndpointAuthMethodNone)
            {
                // **パブリック クライアントは認証しない**（#294）。**秘密を持っていても、それでは通さない。**
                allowed = false;
            }
            else if (registered == OAuth2AndOIDCEnum.AuthMethods.private_key_jwt.ToStringByEmit())
            {
                allowed = (proof == ClientModePolicy.Proof.PrivateKeyJwt);
            }
            else if (registered == OAuth2AndOIDCEnum.AuthMethods.tls_client_auth.ToStringByEmit())
            {
                allowed = (proof == ClientModePolicy.Proof.Mtls);
            }
            else
            {
                // client_secret_basic / client_secret_post
                allowed = (proof == ClientModePolicy.Proof.ClientSecret);
            }

            if (!allowed)
            {
                Logging.MyOperationTrace(string.Format(
                    "The client authentication of {0} was refused. "
                    + "(the registered token_endpoint_auth_method is \"{1}\", but the client proved \"{2}\")",
                    client_id,
                    string.IsNullOrEmpty(registered) ? "(empty)" : registered,
                    proof.ToString()));
            }

            return allowed;
        }

        #endregion

        #region 検証する側の alg（#262。続き）

        /// <summary>登録された alg で絞ってよいか（#262）</summary>
        /// <param name="registeredAlg">登録された alg（null / 空 なら絞らない）</param>
        /// <param name="supported">受ける集合</param>
        /// <param name="actualAlg">実際に来た JWT のヘッダの alg</param>
        /// <returns>通してよければ true</returns>
        /// <remarks>
        /// **3 つに分かれる。**
        ///
        /// | 登録 | 判定 |
        /// |---|---|
        /// | 無い（null / 空） | **通す**（従来どおり。絞らない） |
        /// | 在るが、**受ける集合に無い値** | **拒否**（不正な登録。#224 と同じ方針） |
        /// | 在って、受ける集合の値 | **実際の alg と一致したときだけ通す** |
        ///
        /// **実際の alg が読めないとき（JWT でない等）は拒否**する。
        /// </remarks>
        private static bool AllowsVerifyingAlg(
            string registeredAlg, string[] supported, string actualAlg)
        {
            if (string.IsNullOrEmpty(registeredAlg))
            {
                // 登録が無い ＝ 絞らない。
                return true;
            }

            if (Array.IndexOf(supported, registeredAlg) < 0)
            {
                // **受ける集合に無い値が登録されている**（設定の誤り）。
                return false;
            }

            return !string.IsNullOrEmpty(actualAlg)
                && registeredAlg == actualAlg;
        }

        #endregion

        #endregion

        #endregion
    }
}