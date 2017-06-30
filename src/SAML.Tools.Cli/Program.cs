using SAMLSilly.Config;
using SAMLSilly.Schema.Metadata;
using System;
using System.Linq;
using System.Xml;
using SAMLSilly;
using System.Security.Cryptography.X509Certificates;
using SAMLSilly.Schema.XmlDSig;
using System.Security.Cryptography.Xml;

namespace SAML.Tools.Cli
{
    class Program
    {
        static void Main(string[] args)
        {
            var configSuggestion = new ConfigurationSuggestion();

            var xml = new XmlDocument();
            xml.PreserveWhitespace = true;
            xml.Load("https://auth.uq.edu.au/idp/saml2/idp/metadata.php");

            var meta = new SAMLSilly.Saml20MetadataDocument(xml);
            configSuggestion.SigningDetails = GetSigningInfo(meta.Entity.Signature);


            var sp = meta.Entity.Items.OfType<SpSsoDescriptor>().SingleOrDefault();
            if (sp != null)
            {
                configSuggestion.Sp = GetSpSuggestions(sp);
            }

            var idp = meta.Entity.Items.OfType<IdpSsoDescriptor>().SingleOrDefault();
            if (idp != null)
            {
                configSuggestion.Idp = GetIdpSuggestions(idp);
            }

            Console.WriteLine("The recommend configuration for entityId: {0}", meta.EntityId);
            WriteSigningInfo(configSuggestion.SigningDetails);

            if (configSuggestion.HasSpSupport())
                WriteSsoInfo(configSuggestion.Sp);


            if (configSuggestion.HasIdpSupport())            
                WriteSsoInfo(configSuggestion.Idp);
            


            Console.Read();
        }

        public static void WriteSigningInfo(SigningInfo info)
        {
            Console.WriteLine("Should Use Signed Assertions: {0}", info.IsSigningPossiblyEnabled);
            if (info.IsSigningPossiblyEnabled)
            {
                Console.WriteLine("Recommended Signing Algorithm: {0}", info.RecommendedSigningAlgorithm);
                Console.WriteLine("Is Certificate Valid: {0}", info.IsCertificateValid);
                Console.WriteLine("Is Self Signed Certificate: {0}", info.IsCertificateSelfSigned);
            }
        }

        public static void WriteSsoInfo(SSODescriptorSuggestions sso)
        {
            Console.WriteLine("Identity Provider Details:");
            Console.WriteLine("Supports Single Logout: {0}", sso.SupportsSingleLogout);
            Console.WriteLine("Possibly usable NameId Formats: ");
            foreach (var format in sso.PossiblySupportedNameIdFormats)
            {
                Console.WriteLine("   -   {0}", format);
            }
            WriteSigningInfo(sso.SigningDetails);
        }

        private static SigningInfo GetSigningInfo(SAMLSilly.Schema.XmlDSig.Signature signature)
        {
            var si = new SigningInfo();
            si.IsSigningPossiblyEnabled = signature != null;

            if (si.IsSigningPossiblyEnabled)
            {
                si.RecommendedSigningAlgorithm = ConfigurationHelpers.GetAlgorithmFromNamespace(signature.SignedInfo.SignatureMethod.Algorithm);

                var cert = GetCertificates(signature.KeyInfo);

                var defaultSpec = new SAMLSilly.Specification.DefaultCertificateSpecification();

                si.IsCertificateValid = defaultSpec.IsSatisfiedBy(cert);

                if (!si.IsCertificateValid)
                {
                    var selfSignedSpec = new SAMLSilly.Specification.SelfIssuedCertificateSpecification();
                    si.IsCertificateSelfSigned = selfSignedSpec.IsSatisfiedBy(cert);
                }                
            }
            
            return si;
        }

        public static X509Certificate2 GetCertificates(SAMLSilly.Schema.XmlDSig.KeyInfo keyinfo)
        {

            foreach (var clause in keyinfo.Items.AsEnumerable().Where(x => x is X509Data || x is KeyInfoClause))
            {
                // Check certificate specifications

                if (clause is X509Data)
                {
                    var cert = new X509Certificate2((byte[])((X509Data)clause).Items.First());
                    var keyInfo = new KeyInfoX509Data(cert, X509IncludeOption.WholeChain);
                    
                    return cert;
                }
            }

            return null;
        }

        private static SSODescriptorSuggestions GetIdpSuggestions(IdpSsoDescriptor idp)
        {
            var idpSuggestions = new SSODescriptorSuggestions();

            idpSuggestions.SupportsSingleLogout = idp.SingleLogoutService.Any();
            idpSuggestions.PossiblySupportedNameIdFormats = idp.NameIdFormat;
            idpSuggestions.SigningDetails = GetKeyDescriptorAsWell(idp,GetSigningInfo(idp.Signature));           

            return idpSuggestions;
        }

        private static SSODescriptorSuggestions GetSpSuggestions(SpSsoDescriptor sp)
        {
            var spSuggestions = new SSODescriptorSuggestions();

            spSuggestions.SupportsSingleLogout = sp.SingleLogoutService.Any();
            spSuggestions.PossiblySupportedNameIdFormats = sp.NameIdFormat;
            spSuggestions.SigningDetails = GetKeyDescriptorAsWell(sp,GetSigningInfo(sp.Signature));
            return spSuggestions;
        }

        public static SigningInfo GetKeyDescriptorAsWell(SsoDescriptor sso, SigningInfo si)
        {
            if (si.IsSigningPossiblyEnabled) return si;


            if (sso.KeyDescriptor.Any())
            {
                si.IsSigningPossiblyEnabled = true;
                var a = sso.KeyDescriptor.Select(x => x.KeyInfo).Select(GetCertificates);
                foreach (var cert in a)
                {

                    var defaultSpec = new SAMLSilly.Specification.DefaultCertificateSpecification();

                    si.IsCertificateValid = defaultSpec.IsSatisfiedBy(cert);

                    if (!si.IsCertificateValid)
                    {
                        var selfSignedSpec = new SAMLSilly.Specification.SelfIssuedCertificateSpecification();
                        si.IsCertificateSelfSigned = selfSignedSpec.IsSatisfiedBy(cert);
                    }

                    var sigMeth = cert.SignatureAlgorithm.FriendlyName.ToUpperInvariant();

                    if (sigMeth.Contains(AlgorithmType.SHA1.ToString()))
                    {
                        si.RecommendedSigningAlgorithm = AlgorithmType.SHA1;
                    }
                    else if (sigMeth.Contains(AlgorithmType.SHA256.ToString()))
                    {
                        si.RecommendedSigningAlgorithm = AlgorithmType.SHA256;
                    }
                    else if (sigMeth.Contains(AlgorithmType.SHA512.ToString()))
                    {
                        si.RecommendedSigningAlgorithm = AlgorithmType.SHA1;
                    }

                }
            }

            return si;
        }
        
    }


    public class ConfigurationHelpers
    {
        // public static 


        public static AlgorithmType GetAlgorithmFromNamespace(string namespaceUrl)
        {
            switch (namespaceUrl ?? "")
            {
                case SAMLConstants.XmlDsigRSASHA1Url:
                    {

                        return AlgorithmType.SHA1;
                    }

                case SAMLConstants.XmlDsigRSASHA256Url:
                    {
                        return AlgorithmType.SHA256;

                    }

                case SAMLConstants.XmlDsigRSASHA512Url:
                    {
                        return AlgorithmType.SHA512;
                    }

                default:
                    throw new NotImplementedException();
            }
        }
    }

    public class ConfigurationSuggestion
    {
        public SSODescriptorSuggestions Idp { get; set; }
        public SSODescriptorSuggestions Sp { get; set; }
        public SigningInfo SigningDetails { get; set; }

        public bool HasIdpSupport() => Idp != null;
        public bool HasSpSupport() => Sp != null;

    }

    public class SigningInfo
    {
        public AlgorithmType RecommendedSigningAlgorithm { get; set; } = AlgorithmType.SHA1;
        public bool IsSigningPossiblyEnabled { get; set; }

        public bool IsCertificateValid { get; set; }
        public bool IsCertificateSelfSigned { get; set; }
    }

    public class SSODescriptorSuggestions
    {
        public string[] PossiblySupportedNameIdFormats { get; set; }
        public bool SupportsSingleLogout { get; set; }
        public bool SupportsSingleSignOn { get; set; }
        public SigningInfo SigningDetails { get; set; }


    }


    public static class SAMLConstants
    {
        //Value from System.Security.Cryptography.Xml.SignedXml.XmlDsigRSASHA1Url
        public const string XmlDsigRSASHA1Url = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

        //This is not included in the SAML standard but everyone supports it as SHA1 is deprecated
        public const string XmlDsigRSASHA256Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

        //For future proofing
        public const string XmlDsigRSASHA512Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    }

}
