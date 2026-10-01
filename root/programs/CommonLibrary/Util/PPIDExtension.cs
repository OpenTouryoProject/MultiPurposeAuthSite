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
//* クラス名        ：PPIDExtension
//* クラス日本語名  ：PPIDExtension（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2020/01/07  西野 大介         新規
//*  2026/09/30  玄人 幸道         PPID を OP だけが戻せる形にした（#140 の段階 2）
//*  2026/10/02  玄人 幸道         subject_types を public / pairwise の 2 つにした（#151 の段階 5）
//**********************************************************************************

#if NETFX
using MultiPurposeAuthSite.Entity;
#else
//
#endif

using System;
using System.Security.Cryptography;

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Extensions.Sts;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.Util
{
    /// <summary>PPIDExtension</summary>
    public static class PPIDExtension
    {
        #region public

        #region GetSubForXXXX
        /// <summary>
        /// userNameから、設定に従ってsubを取得する。
        /// </summary>
        /// <param name="iss">string</param>
        /// <param name="userName">string</param>
        /// <param name="nameIDFormat">SAML2Enum.NameIDFormat</param>
        /// <returns>sub</returns>
        public static string GetSubForSAML2(string iss, string userName, SAML2Enum.NameIDFormat nameIDFormat)
        {
            ApplicationUser user = null;
            string sub = PPIDExtension.GetSubForOIDC(iss, userName, out user);

            switch (nameIDFormat)
            {
                case SAML2Enum.NameIDFormat.Unspecified:
                    //sub = sub;
                    break;
                case SAML2Enum.NameIDFormat.EmailAddress:
                    sub = user.Email;
                    break;
                case SAML2Enum.NameIDFormat.Persistent:
                    sub = PPIDExtension.GeneratePPIDByUserID(iss, user.Id);
                    break;
                //case SAML2Enum.NameIDFormat.Transient:
                //    sub = "????";
                //    break;
            }

            return sub;
        }

        /// <summary>
        /// userNameから、設定に従ってsubを取得する。
        /// </summary>
        /// <param name="clientId">string</param>
        /// <param name="userName">string</param>
        /// <param name="user">ApplicationUser</param>
        /// <returns>sub</returns>
        public static string GetSubForOIDC(string clientId, string userName, out ApplicationUser user)
        {
            string sub = "";
            user = null;

            if (string.IsNullOrEmpty(userName))
            {
                // Client認証
                sub = Helper.GetInstance().GetClientName(clientId);
            }
            else
            {
                user = CmnUserStore.FindByName(userName);

                if (user == null)
                {
                    // Client認証
                    sub = userName;
                }
                else
                {
                    // Resource Owner認証
                    string subjectTypes = Helper.GetInstance().GetSubjectTypes(clientId);

                    // **pairwise だけが別**（それ以外は public。既定も public）。
                    if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit())
                    {
                        sub = PPIDExtension.GeneratePPIDByUserID(clientId, user.Id); // PPID
                    }
                    else
                    {
                        sub = user.Id;
                    }

                    // **発行した sub を記録し、2 回目以降はそこから返す**（#151 の段階 2）。
                    //   **計算し直さない**ので、`subject_types` の既定や PPID の作り方を変えても、
                    //   **発行済みの sub は動かない**（RP は sub を主キーとして保存している）。
                    //   **pairwise 専用ではなく、public も入れる。**
                    //   そうしないと、既定値の変更を無害にできない。
                    sub = SubjectIdProvider.GetOrAdd(
                        PPIDExtension.GetSector(clientId), user.Id, sub);
                }
            }
            return sub;
        }
        #endregion

        #region GetUserFromSub
        /// <summary>
        /// 設定に従ったsubから、ApplicationUserを取得する。
        /// </summary>
        /// <param name="clientId">string</param>
        /// <param name="sub">string</param>
        /// <returns>ApplicationUser</returns>
        public static ApplicationUser GetUserFromSub(string clientId, string sub)
        {
            string subjectTypes = "";
            return PPIDExtension.GetUserFromSub(clientId, sub, out subjectTypes);
        }

        /// <summary>
        /// 設定に従ったsubから、ApplicationUserを取得する。
        /// </summary>
        /// <param name="clientId">string</param>
        /// <param name="sub">string</param>
        /// <param name="subjectTypes">string</param>
        /// <returns>ApplicationUser</returns>
        public static ApplicationUser GetUserFromSub(string clientId, string sub, out string subjectTypes)
        {
            ApplicationUser user = null;

            subjectTypes = Helper.GetInstance().GetSubjectTypes(clientId);

            // **まず対応表を引く**（#151 の段階 2）。
            //   **発行したときに記録してある**ので、**いまの subject_types の設定に関わらず引ける。**
            //   設定を変えた後でも、**以前の sub を持つ RP が壊れない**のはここが効くため。
            string recordedUserId = SubjectIdProvider.GetUserId(
                PPIDExtension.GetSector(clientId), sub);

            if (!string.IsNullOrEmpty(recordedUserId))
            {
                user = CmnUserStore.FindById(recordedUserId);

                if (user != null)
                {
                    return user;
                }
            }

            // **表に無い場合は、従来どおり subject_types で引く。**
            //   表を入れる前に発行した sub、または利用者が削除された場合。
            // **pairwise だけが別**（それ以外は public。既定も public）。
            if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit())
            {
                // **PPID を復号して UserID を取り出す**（#140 の段階 2）。
                //   以前は「取りようが無いので...。」と null を返していた。
                //   そのため **/userinfo がクレームを返さず、ciba_result は 401** になっていた。
                //
                //   **復元できても、実在する利用者かは確かめる**（外から来た値なので）。
                //   FindById が null を返せば、そのまま null になる。
                string userId = PPIDExtension.GetUserIDFromPPID(clientId, sub);

                user = string.IsNullOrEmpty(userId) ? null : CmnUserStore.FindById(userId);
            }
            else
            {
                user = CmnUserStore.FindById(sub);
            }

            return user;
        }
        #endregion

        /// <summary>GetUserFromSubのヌルポ対策で実装</summary>
        /// <param name="clientId">string</param>
        /// <param name="sub">string</param>
        /// <returns>userName</returns>
        /// <remarks>
        /// **pairwise でも利用者名を返せるようになった**（#140 の段階 2）。
        /// 以前は復元できなかったため `"PPID: " + sub` を返しており、
        /// **オペレーション ログが PPID のままで読めず**、
        /// **`id_token_hint` から利用者を引く経路（#232）も成立していなかった。**
        ///
        /// **復元できない場合は、従来どおり `"PPID: " + sub` を返す**
        /// （他のクライアント向けの値や、削除済みの利用者）。
        /// </remarks>
        public static string GetUserNameFromSub(string clientId, string sub)
        {
            string subjectTypes = "";
            ApplicationUser user = PPIDExtension.GetUserFromSub(clientId, sub, out subjectTypes);

            if (user != null)
            {
                return user.UserName;        // Resource Owner認証
            }

            if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit())
            {
                return "PPID: " + sub;       // 復元できなかった PPID
            }

            return "";                       // Client認証
        }

        #endregion

        #region private

        /// <summary>client_id から Sector Identifier を決める（#151 の段階 2）</summary>
        /// <param name="clientId">client_id</param>
        /// <returns>Sector Identifier</returns>
        /// <remarks>
        /// **いまは `client_id` をそのまま返す。**
        ///
        /// **本来の Sector Identifier は、クライアントではなく RP の単位**である
        /// （OIDC Core §8.1。`sector_identifier_uri` が在ればそのホスト、
        /// 無ければ `redirect_uri` のホスト）。
        /// **`sector_identifier_uri` は未対応**なので、いまは `client_id` が Sector である。
        /// **同じ RP の複数クライアントで `sub` が変わる**のは、そのためである。
        ///
        /// **対応するときは、ここだけを直せばよい。**
        /// 対応表（`SubjectIdentifier`）の列は **`Sector`**（意味）で持っているので、
        /// **既存行はそのまま有効**である（発行済みの `sub` は動かない）。
        /// </remarks>
        private static string GetSector(string clientId)
        {
            return clientId ?? "";
        }

        /// <summary>
        /// UserIDからclientIdを使用して、PPID（Pairwise Pseudonymous Identifier）を生成する。
        /// SAMLと共通化するにredirect_urlだと対応するACS URLが登録されていないので。
        /// </summary>
        /// <param name="clientId">string（sector identifier）</param>
        /// <param name="userId">string</param>
        /// <returns>PPID</returns>
        /// <remarks>
        /// **OP だけが戻せる暗号化**である（#140 の段階 2）。
        ///
        /// **以前は salted hash（一方向）だった。**
        /// ```
        /// sub = SHA-256 ( sector_identifier || local_account_id || salt )
        /// ```
        /// **一方向なので戻せず、`GetUserFromSub` が `pairwise` で null を返していた。**
        /// その結果、**`/userinfo` がクレームを返さず、`ciba_result` は 401 になっていた**
        /// （`subject_types=pairwise` のクライアントでは、機能が成立していなかった）。
        ///
        /// **pairwise に求められるのは「OP 以外が戻せないこと」**である。
        /// 一方向であることは求められていない。**OP だけが鍵を持つ暗号化は、その条件を満たす。**
        ///
        /// **決定的でなければならない。** RP は `sub` を利用者の主キーとして保存するため、
        /// **同じ利用者・同じクライアントなら、常に同じ値**でなければならない。
        /// `SymmetricCryptography` は鍵と IV を **PBKDF2 で パスワードとソルトから導出**するので、
        /// **同じ入力なら常に同じ暗号文**になる（乱数の IV を使っていない）。
        ///
        /// **クライアントごとに変わること**も要る（pairwise の目的）。
        /// **ソルトに `client_id` を入れる**ことで、鍵と IV がクライアントごとに変わる。
        ///
        /// > **制約 : 秘密（`SaltParameter`）を替えると、発行済みの PPID が全部変わる。**
        /// > **RP は `sub` を主キーとして保存している**ため、**RP 側で全員が別人になる。**
        /// > これは**以前の salted hash でも同じ**で、この変更で悪くなってはいない。
        /// > **漏洩時に「替えられない」**のが弱いところで、解くには対応表が要る
        /// > （`client_id` × `user_id` → PPID を保存する）。
        /// > **導出が決定的なので、鍵を替える前に全組み合わせを計算して表に入れれば、
        /// > 発行済みの値を保ったまま移行できる**（D-9 の鍵ローテーションと同じ性質の宿題）。
        /// </remarks>
        private static string GeneratePPIDByUserID(string clientId, string userId)
        {
            return CustomEncode.ToBase64UrlString(
                PPIDExtension.Transform(
                    clientId, CustomEncode.StringToByte(userId, CustomEncode.UTF_8), true));
        }

        /// <summary>PPIDからclientIdを使用して、UserIDを復元する。</summary>
        /// <param name="clientId">string（sector identifier）</param>
        /// <param name="ppid">PPID</param>
        /// <returns>UserID（復元できなければ空文字）</returns>
        /// <remarks>
        /// **外から来た値を渡される**（アクセス トークンの `sub`）ので、**例外にしない。**
        /// 他のクライアント向けの PPID や、でたらめな値を渡されれば復元に失敗する。
        /// **復元できても、それが実在する利用者かは呼び出し側が確かめる。**
        /// </remarks>
        private static string GetUserIDFromPPID(string clientId, string ppid)
        {
            if (string.IsNullOrEmpty(ppid))
            {
                return "";
            }

            try
            {
                return CustomEncode.ByteToString(
                    PPIDExtension.Transform(
                        clientId, CustomEncode.FromBase64UrlString(ppid), false),
                    CustomEncode.UTF_8);
            }
            catch
            {
                // 復元できない値（他のクライアント向け・でたらめ・改竄）
                return "";
            }
        }

        /// <summary>クライアント（sector）ごとの鍵で、AES-CBC で変換する。</summary>
        /// <param name="clientId">string（sector identifier）</param>
        /// <param name="input">入力</param>
        /// <param name="encrypt">true なら暗号化、false なら復号</param>
        /// <returns>変換後</returns>
        /// <remarks>
        /// **Open棟梁 の `SymmetricCryptography` は使わない。**
        /// `EncryptBytes` / `DecryptBytes` が通る `GenerateKeyFromPassword`（7 引数）が
        /// **「overloadへ」と書きながら自分自身を呼んでおり、無限再帰する**
        /// （`Public/Security/SymmetricCryptography.cs`）。**スタック オーバーフローでプロセスが落ちる。**
        /// 実装で踏んで切り分けた（#140 の段階 2）。**上流の不具合。**
        ///
        /// **鍵と IV は、秘密（`SaltParameter`）と `client_id` から決定的に導出する。**
        /// ・**決定的**でなければならない（RP は `sub` を主キーとして保存するため）
        /// ・**クライアントごとに変わる**必要がある（pairwise の目的）
        ///
        /// **ストレッチング（PBKDF2）は使わない。** 元が利用者のパスワードではなく
        /// **サーバの秘密**なので、総当たりを遅くする意味が無い。
        /// **トークン発行のたびに通る経路**なので、無駄に重くしない。
        /// </remarks>
        private static byte[] Transform(string clientId, byte[] input, bool encrypt)
        {
            byte[] secret = CustomEncode.StringToByte(Config.SaltParameter ?? "", CustomEncode.UTF_8);
            byte[] sector = CustomEncode.StringToByte(clientId ?? "", CustomEncode.UTF_8);

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                aes.Key = PPIDExtension.Derive(secret, "ppid-key", sector, 32);
                aes.IV = PPIDExtension.Derive(secret, "ppid-iv", sector, 16);

                using (ICryptoTransform transform =
                    encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor())
                {
                    return transform.TransformFinalBlock(input, 0, input.Length);
                }
            }
        }

        /// <summary>秘密・用途・sector から、鍵材料を導出する。</summary>
        /// <param name="secret">秘密（SaltParameter）</param>
        /// <param name="label">用途（鍵と IV を別の値にするため）</param>
        /// <param name="sector">sector identifier（client_id）</param>
        /// <param name="length">必要なバイト数（32 以下）</param>
        /// <returns>鍵材料</returns>
        private static byte[] Derive(byte[] secret, string label, byte[] sector, int length)
        {
            byte[] labelBytes = CustomEncode.StringToByte(label, CustomEncode.UTF_8);
            byte[] source = new byte[secret.Length + labelBytes.Length + sector.Length];

            Buffer.BlockCopy(secret, 0, source, 0, secret.Length);
            Buffer.BlockCopy(labelBytes, 0, source, secret.Length, labelBytes.Length);
            Buffer.BlockCopy(sector, 0, source, secret.Length + labelBytes.Length, sector.Length);

            byte[] hash = GetHash.GetHashBytes(source, EnumHashAlgorithm.SHA256);  // 32 バイト
            byte[] material = new byte[length];

            Buffer.BlockCopy(hash, 0, material, 0, length);

            return material;
        }

        #endregion
    }
}