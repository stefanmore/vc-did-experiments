package systems.failing.experiments;

import com.danubetech.verifiablecredentials.CredentialSubject;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.jsonld.VerifiableCredentialContexts;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2018LdSigner;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2018LdVerifier;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

/**
 * Verifiable Credentials with Linked Data Proofs.
 * Examples from https://github.com/danubetech/verifiable-credentials-java/blob/main/examples-ldp.md
 */
public class LdpExamplesTest {
    
    
    @Test
    public void exampleCreateTest() throws DecoderException, JsonLDException, GeneralSecurityException, IOException {
        // signing example from https://github.com/danubetech/verifiable-credentials-java/blob/main/examples-ldp.md#example-code-signing
        
        Map<String, Object> claims = new LinkedHashMap<>();
        Map<String, Object> degree = new LinkedHashMap<String, Object>();
        degree.put("name", "Bachelor of Science and Arts");
        degree.put("type", "BachelorDegree");
        claims.put("college", "Test University");
        claims.put("degree", degree);
        
        CredentialSubject credentialSubject = CredentialSubject.builder()
                .id(URI.create("did:example:ebfeb1f712ebc6f1c276e12ec21"))
                .claims(claims)
                .build();
        
        VerifiableCredential verifiableCredential = VerifiableCredential.builder()
                .context(VerifiableCredentialContexts.JSONLD_CONTEXT_W3C_2018_CREDENTIALS_EXAMPLES_V1)
                .type("UniversityDegreeCredential")
                .id(URI.create("http://example.edu/credentials/3732"))
                .issuer(URI.create("did:example:76e12ec712ebc6f1c221ebfeb1f"))
                .issuanceDate(JsonLDUtils.stringToDate("2019-06-16T18:56:59Z"))
                .expirationDate(JsonLDUtils.stringToDate("2019-06-17T18:56:59Z"))
                .credentialSubject(credentialSubject)
                .build();
        
        byte[] testEd25519PrivateKey = Hex.decodeHex("984b589e121040156838303f107e13150be4a80fc5088ccba0b0bdc9b1d89090de8777a28f8da1a74e7a13090ed974d879bf692d001cddee16e4cc9f84b60580".toCharArray());
        
        Ed25519Signature2018LdSigner signer = new Ed25519Signature2018LdSigner(testEd25519PrivateKey);
        signer.setCreated(new Date());
        signer.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD);
        signer.setVerificationMethod(URI.create("did:example:76e12ec712ebc6f1c221ebfeb1f#keys-1"));
        signer.setDomain("example.com");
        signer.setNonce(UUID.randomUUID().toString());
        LdProof ldProof = signer.sign(verifiableCredential);
        
        try(final FileWriter fileWriter = new FileWriter("/tmp/LdpExample.jsonld")) {
            fileWriter.write(verifiableCredential.toJson(true));
        }
        
        System.out.println(verifiableCredential.toJson(true));
    }
    
    @Test
    public void exampleVerifyTest() throws DecoderException, JsonLDException, GeneralSecurityException, IOException {
        // verification example from https://github.com/danubetech/verifiable-credentials-java/blob/main/examples-ldp.md#example-code-verifying
        
        byte[] testEd25519PublicKey = Hex.decodeHex("de8777a28f8da1a74e7a13090ed974d879bf692d001cddee16e4cc9f84b60580".toCharArray());
        
        VerifiableCredential verifiableCredential = VerifiableCredential.fromJson(new FileReader("/tmp/LdpExample.jsonld"));
        
        
        //LdVerifier<? extends SignatureSuite> verifier = LdVerifierRegistry.getLdVerifierBySignatureSuiteTerm(verifiableCredential.getLdProof().getType());
        Ed25519Signature2018LdVerifier verifier = new Ed25519Signature2018LdVerifier(testEd25519PublicKey);
        
        assertEquals(verifier.getSignatureSuite().getTerm(), verifiableCredential.getLdProof().getType());
        
        System.out.println("Verify credential using key: " + verifiableCredential.getLdProof().getVerificationMethod());
        
        System.out.println(verifier.verify(verifiableCredential));
        
    }
    
}
