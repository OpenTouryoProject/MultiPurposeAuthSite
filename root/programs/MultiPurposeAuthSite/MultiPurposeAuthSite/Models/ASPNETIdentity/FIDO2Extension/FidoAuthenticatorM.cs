using System;
using System.Text;
using System.Web.Script.Serialization;
using System.Security.Cryptography;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.FIDO2Extension
{
    public class FidoAuthenticatorM
    {
        public const string Challenge = "Y2xpbWIgYSBtb3VudGFpbg";
        public const string PublicKey = "{ \"kty\" : \"RSA\", \"alg\" : \"RS256\", \"ext\" : false, \"n\" : \"k-d_ZbVlAu-EBhRNlevnd0cBqJEPlhBefOMMLgHeGTS28Uev6_xHVCZ774I2XdtVF-M5En0aTdekAX82K2SVnO9TEZ4GdJFR1kW1jppLtrlUyjQqggq60OwkUxHM14XDQBhvgeW3fjpETraB-R_scyGeK7lNWMF8jW-NjvU_nljTyuHoDVnYJxPuCunlQ7uzg80iURp0jFKhw7FedPkzyQllG0HRRfzwQG1WOyECxkdPmMk7iPdF-B-Z78S9Fd8Dx2R8OZHEpFMdQ3Z3bMLG8prSbXcmBXlBtmwSLPzEEb3FuPdJQtXzVyg2i3jAR25zWA_XemXHBv7XE5Mf3JYldQ\", \"e\" : \"AQAB\" }";
        public const string AuthnrData = "AQAAAAA";
        public const string ClientData = "ew0KCSJjaGFsbGVuZ2UiIDogIlkyeHBiV0lnWVNCdGIzVnVkR0ZwYmciLA0KCSJ1c2VyUHJvbXB0IiA6ICJIZWxsbyEiDQp9AA";
        public const string Signature = "M-GT64y3FXoFQI8fRPq8ogckxuVYqv65R2eJEXGpbmVtm3Zn9Oa6ik4nClFMsN4h42e9bSBslMTEKW-J1oAoxF8n4JkDH82b9j4bFhhSRMHCbmE-uZm1RX8zVrGIgoWnXDy2nGQSu5xN-BhGubru1x0sXo9ZAdXKc-5hkp6SfIdXAY15o9flsag_H_CpIJ1_L1-vO5K8xhya_iOezflNlqa8-D1lI-xMJ7dOqyPwqg33ryW4l6iTtexuiYhZaGOOyJ5ZxzchjKrw9zMgQOsjbsrM7Q6bu7K7YvOoULxM5WJFdCLj0OBZznrskEHlLrSe0TSr_WrY1SkLhRaUCetKkg";

        /*
         * The FidoAuthenticator class contains the logic for validating the signature returned from getAssertion in the
         * browser. This code is currently specific to the early implementation in Microsoft Edge and will need to change
         * when the final standard is adopted. This code would run on the server in order to validate that the user
         * really is able to validate using the credentials previously created with the makeCredential API.
         *
         * The public key in pk would have been stored on the server using the results of makeCredential. The challenge
         * would have been created on ther server and sent to the client for use in the getAssertion call. The other
         * parameters are returned by getAssertion and transmitted from the browser to the server for validation. 
         * 
         * FidoAuthenticatorクラスには、ブラウザのgetAssertionから返されたシグネチャを検証するロジックが含まれています。
         * このコードは現在、Microsoft Edgeの初期導入に固有のものであり、最終的な標準が採用された時点で変更する必要があります。
         * このコードは、ユーザーが実際にmakeCredential APIで作成した認証情報を使用して検証できることを検証するためにサーバー上で実行されます
         * pkの公開鍵は、makeCredentialの結果を使用してサーバーに格納されていました。
         * チャレンジは、サーバー上で作成され、クライアントに送信されてgetAssertionコールで使用されます。
         * 他のパラメータはgetAssertionによって返され、検証のためにブラウザからサーバに送信されます。
        */
        public static bool validateSignature(string pk, string clientData, string authnrData, string signature, string challenge)
        {
            try
            {
                var c = rfc4648_base64_url_decode(clientData);
                var a = rfc4648_base64_url_decode(authnrData);
                var s = rfc4648_base64_url_decode(signature);

                // Make sure the challenge in the client data matches the expected challenge
                var cc = Encoding.ASCII.GetString(c);
                cc = cc.Replace("\0", "").Trim();
                var json = new JavaScriptSerializer();
                var j = (System.Collections.Generic.Dictionary<string, object>)json.DeserializeObject(cc);
                if ((string)j["challenge"] != challenge) return false;

                // Hash data with sha-256
                var hash = new SHA256Managed();
                var h = hash.ComputeHash(c);

                // Create data buffer to verify signature over
                var b = new byte[a.Length + h.Length];
                a.CopyTo(b, 0);
                h.CopyTo(b, a.Length);

                // Load public key
                j = (System.Collections.Generic.Dictionary<string, object>)json.DeserializeObject(pk);
                var keyinfo = new RSAParameters();
                keyinfo.Modulus = rfc4648_base64_url_decode((string)j["n"]);
                keyinfo.Exponent = rfc4648_base64_url_decode((string)j["e"]);
                var rsa = new RSACng();
                rsa.ImportParameters(keyinfo);

                // Verify signature is correct for authnrData + hash
                return rsa.VerifyData(b, s, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static byte[] rfc4648_base64_url_decode(string url)
        {
            url = url.Replace('-', '+');
            url = url.Replace('_', '/');

            switch (url.Length % 4)
            { // Pad with trailing '='s
                case 0:
                    // No pad chars in this case
                    break;
                case 2:
                    // Two pad chars
                    url += "==";
                    break;
                case 3:
                    // One pad char
                    url += "=";
                    break;
                default:
                    throw new Exception("Invalid string.");
            }
            return Convert.FromBase64String(url);
        }
    }
}