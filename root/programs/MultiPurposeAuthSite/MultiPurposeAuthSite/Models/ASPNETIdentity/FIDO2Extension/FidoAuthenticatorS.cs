using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json.Linq;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.FIDO2Extension
{
    public class FidoAuthenticatorS
    {
        public FidoAuthenticatorS(string publicKey, string challenge)
        {
            _publicKey = publicKey;
            _challenge = challenge;
        }

        private readonly string _publicKey;
        private readonly string _challenge;

        public bool ValidateSignature(string signature, string authenticatorData, string clientData)
        {
            var jwk = JObject.Parse(_publicKey);

            var rsaParameters = new RSAParameters
            {
                Modulus = FromBase64Url((string)jwk["n"]),
                Exponent = FromBase64Url((string)jwk["e"])
            };

            var signatureBytes = FromBase64Url(signature);
            var authenticatorDataBytes = FromBase64Url(authenticatorData);
            var clientDataBytes = FromBase64Url(clientData);
            
            var clientJson = JObject.Parse(Encoding.ASCII.GetString(clientDataBytes));
            
            if ((string)clientJson["challenge"] != _challenge)
            {
                return false;
            }

            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(clientDataBytes);

            var data = authenticatorDataBytes.Concat(hash).ToArray();

            var rsa = RSA.Create();

            rsa.ImportParameters(rsaParameters);

            return rsa.VerifyData(data, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        private static byte[] FromBase64Url(string url)
        {
            url = url.Replace('-', '+');
            url = url.Replace('_', '/');

            switch (url.Length % 4)
            {

                case 0:
                    break;

                case 2:
                    url += "==";
                    break;

                case 3:
                    url += "=";
                    break;

                default:
                    throw new ArgumentException();
            }

            return Convert.FromBase64String(url);
        }
    }
}