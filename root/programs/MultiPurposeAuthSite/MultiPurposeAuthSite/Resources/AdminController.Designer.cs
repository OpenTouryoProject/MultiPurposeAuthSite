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
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class AdminController {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal AdminController() {
        }
        
        /// <summary>
        ///   このクラスで使用されているキャッシュされた ResourceManager インスタンスを返します。
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("MultiPurposeAuthSite.Resources.AdminController", typeof(AdminController).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   厳密に型指定されたこのリソース クラスを使用して、すべての検索リソースに対し、
        ///   現在のスレッドの CurrentUICulture プロパティをオーバーライドします。
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Add is succeeded. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        internal static string AddSuccess {
            get {
                return ResourceManager.GetString("AddSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Delete is succeeded. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        internal static string DeleteSuccess {
            get {
                return ResourceManager.GetString("DeleteSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Do not have ownership of this object. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        internal static string DoNotHaveOwnershipOfTheObject {
            get {
                return ResourceManager.GetString("DoNotHaveOwnershipOfTheObject", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Edit is succeeded. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        internal static string EditSuccess {
            get {
                return ResourceManager.GetString("EditSuccess", resourceCulture);
            }
        }
        
        /// <summary>
        ///   An error has occurred. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        internal static string Error {
            get {
                return ResourceManager.GetString("Error", resourceCulture);
            }
        }
        
        /// <summary>
        ///   This request has not been authenticated. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        internal static string UnAuthenticate {
            get {
                return ResourceManager.GetString("UnAuthenticate", resourceCulture);
            }
        }
        
        /// <summary>
        ///   With the granted privilege, this operation is not authorized. に類似しているローカライズされた文字列を検索します。
        /// </summary>
        internal static string UnAuthorized {
            get {
                return ResourceManager.GetString("UnAuthorized", resourceCulture);
            }
        }
    }
}
