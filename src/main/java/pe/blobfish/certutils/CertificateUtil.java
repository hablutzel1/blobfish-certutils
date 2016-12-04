package pe.blobfish.certutils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Vector;

/**
 * Contains methods to ease the task to get information in the signer certificate
 */
public class CertificateUtil {

    public static String getSubjectName(X509Certificate signerCertificate) {
        // TODO display a friendly name for the subject, consider that it is not an obligation for a certificate to contain a commonName attribute (RFC 3739 3.1.2. Subject, ETSI TS 119 412-2 V1.2.1 5.2.6), see for a solution: http://www.ldapexplorer .com/en/manual/103031800-view-show-friendly-names.htm, http://php.net/manual/en/function.ldap-dn2ufn.php RFC 1779, RFC 1781
        // TODO evaluate to return the full DN if the CN is not found.
        return getFirstSubjectAttributeValue(signerCertificate, BCStyle.CN);
    }

    public static String getIssuerName(X509Certificate signerCertificate) {
        // TODO consider something similar to pe.blobfish.certutils.CertificateUtil.getSubjectName
        return getFirstIssuerAttributeValue(signerCertificate, BCStyle.CN);
    }

    public static String getSubjectOrganization(X509Certificate signerCertificate) {
        return getFirstSubjectAttributeValue(signerCertificate, BCStyle.O);
    }

    // TODO evaluate to create more methods to get certificate data easily, check RFC 3739 for mandatory and optional
    // fields expected in a qualified certificate

    private static String getFirstSubjectAttributeValue(X509Certificate x509Certificate, ASN1ObjectIdentifier attributeIdentifier) {
        // TODO evaluate to migrate to 'javax.naming.ldap.LdapName' as its API (ABI ?) seems more stable than the BC which is changing for example, from 1.44 to 1.49 disallowing this code to be used with both versions, first check in which Java version 'javax.naming.ldap.LdapName' got introduced.
        X509Principal principal;
        try {
            principal = PrincipalUtil.getSubjectX509Principal(x509Certificate);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }

        return getFirstPrincipalAttributeValue(principal, attributeIdentifier);
    }

    private static String getFirstIssuerAttributeValue(X509Certificate x509Certificate, ASN1ObjectIdentifier attributeIdentifier) {

        X509Principal principal;
        try {
            principal = PrincipalUtil.getIssuerX509Principal(x509Certificate);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }

        return getFirstPrincipalAttributeValue(principal, attributeIdentifier);
    }

    private static String getFirstPrincipalAttributeValue(X509Principal principal, ASN1ObjectIdentifier attributeIdentifier) {
        Vector values = principal.getValues(attributeIdentifier);
        if (values.size() > 0) {
            // TODO confirm that it actually returns the "first" attribute value, confirm concept of order in spec.
            // casting to string as expected values for attributes are only strings like types rfc 5280 4.1.2.4. Issuer.
            return (String) values.get(0);
        }
        return null;
    }

}
