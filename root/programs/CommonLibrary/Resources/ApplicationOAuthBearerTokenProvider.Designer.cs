﻿//------------------------------------------------------------------------------
// <auto-generated>
//     このコードはツールによって生成されました。
//     ランタイム バージョン:4.0.30319.42000
//
//     このファイルへの変更は、以下の状況下で不正な動作の原因になったり、
//     コードが再生成されるときに損失したりします。
// </auto-generated>
//------------------------------------------------------------------------------

namespace MultiPurposeAuthSite.Resources {
    using System;
    
    
    /// <summary>
    ///   ローカライズされた文字列などを検索するための、厳密に型指定されたリソース クラスです。
    /// </summary>
    // このクラスは StronglyTypedResourceBuilder クラスが ResGen
    // または Visual Studio のようなツールを使用して自動生成されました。
    // メンバーを追加または削除するには、.ResX ファイルを編集して、/str オプションと共に
    // ResGen を実行し直すか、または VS プロジェクトをビルドし直します。
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "16.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    public class ApplicationOAuthBearerTokenProvider {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal ApplicationOAuthBearerTokenProvider() {
        }
        
        /// <summary>
        ///   このクラスで使用されているキャッシュされた ResourceManager インスタンスを返します。
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        public static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("MultiPurposeAuthSite.Resources.ApplicationOAuthBearerTokenProvider", typeof(ApplicationOAuthBearerTokenProvider).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   すべてについて、現在のスレッドの CurrentUICulture プロパティをオーバーライドします
        ///   現在のスレッドの CurrentUICulture プロパティをオーバーライドします。
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        public static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   The resource owner credentials are invalid or resource owner does not exist. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string access_denied {
            get {
                return ResourceManager.GetString("access_denied", resourceCulture);
            }
        }
        
        /// <summary>
        ///   client_id not sett. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string client_id_NotSett {
            get {
                return ResourceManager.GetString("client_id_NotSett", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Authorization Code grant type is not enabled. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string EnableAuthorizationCodeGrantType {
            get {
                return ResourceManager.GetString("EnableAuthorizationCodeGrantType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   CIBA grant type is not enabled. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string EnableCibaGrantType {
            get {
                return ResourceManager.GetString("EnableCibaGrantType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Client Credentials grant type is not enabled. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string EnableClientCredentialsGrantType {
            get {
                return ResourceManager.GetString("EnableClientCredentialsGrantType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Implicit grant type is not enabled. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string EnableImplicitGrantType {
            get {
                return ResourceManager.GetString("EnableImplicitGrantType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Refresh Token is not enabled. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string EnableRefreshToken {
            get {
                return ResourceManager.GetString("EnableRefreshToken", resourceCulture);
            }
        }
        
        /// <summary>
        ///   ResourceOwner Credentials grant type is not enabled. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string EnableResourceOwnerCredentialsGrantType {
            get {
                return ResourceManager.GetString("EnableResourceOwnerCredentialsGrantType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Invalid client_id. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string Invalid_client_id {
            get {
                return ResourceManager.GetString("Invalid_client_id", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Invalid redirect_uri. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string Invalid_redirect_uri {
            get {
                return ResourceManager.GetString("Invalid_redirect_uri", resourceCulture);
            }
        }
        
        /// <summary>
        ///   redirect_uri not registered. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string redirect_uri_NotRegistered {
            get {
                return ResourceManager.GetString("redirect_uri_NotRegistered", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Could not retrieve the user. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string server_error1 {
            get {
                return ResourceManager.GetString("server_error1", resourceCulture);
            }
        }
        
        /// <summary>
        ///   The ClaimsIdentity could not be created by the UserManager. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        public static string server_error2 {
            get {
                return ResourceManager.GetString("server_error2", resourceCulture);
            }
        }
    }
}
