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
//**********************************************************************************

#if NETFX
using MultiPurposeAuthSite.Entity;
#else
//
#endif

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

                    if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.@public.ToStringByEmit())
                    {
                        sub = user.Id;
                    }
                    else if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit())
                    {
                        sub = PPIDExtension.GeneratePPIDByUserID(clientId, user.Id); // PPID
                    }
                    else //if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.uname.ToStringByEmit())
                    {
                        // 汎用認証サイトのデフォルト値（仕様）
                        sub = userName;
                    }
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
            
            if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.@public.ToStringByEmit())
            {
                user = CmnUserStore.FindById(sub);
            }
            else if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit())
            {
                // 取りようが無いので...。
                user = null;
            }
            else //if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.uname.ToStringByEmit())
            {
                // 汎用認証サイトのデフォルト値（仕様）
                user = CmnUserStore.FindByName(sub);
            }

            return user;
        }
        #endregion

        /// <summary>GetUserFromSubのヌルポ対策で実装</summary>
        /// <param name="clientId">string</param>
        /// <param name="sub">string</param>
        /// <returns>userName</returns>
        public static string GetUserNameFromSub(string clientId, string sub)
        {
            string subjectTypes = "";
            ApplicationUser user = PPIDExtension.GetUserFromSub(clientId, sub, out subjectTypes);

            if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit())
            {
                return "PPID: " + sub;       // PPID
            }
            else
            {
                if (user == null) return ""; // Client認証
                else return user.UserName;   // Resource Owner認証 
            }
        }

        #endregion

        #region private
        /// <summary>
        /// UserIDからclientIdを使用して、PPID（Pairwise Pseudonymous Identifier）を生成する。
        /// SAMLと共通化するにredirect_urlだと対応するACS URLが登録されていないので。
        /// </summary>
        /// <param name="clientId">string</param>
        /// <param name="userId">string</param>
        /// <returns></returns>
        private static string GeneratePPIDByUserID(string clientId, string userId)
        {
            // sub = SHA-256 ( sector_identifier || local_account_id || salt )
            byte[] asb = CustomEncode.StringToByte(clientId + userId + Config.SaltParameter, CustomEncode.UTF_8);
            return CustomEncode.ToBase64UrlString(GetHash.GetHashBytes(asb, EnumHashAlgorithm.SHA256_M));
        }
        #endregion
    }
}