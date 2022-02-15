package systems.failing.experiments;

import com.danubetech.verifiablecredentials.CredentialSubject;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.jsonld.VerifiableCredentialContexts;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDException;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2020LdSigner;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import io.ipfs.multibase.Multibase;
import org.bitcoinj.core.Base58;
import org.junit.Test;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.result.ResolveRepresentationResult;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static org.junit.Assert.*;

public class fullTest {
    
    public static final String TESTKEY_ISSUER = "nodejs/testkey1.json";
    public static final String TESTKEY_SUBJECT = "nodejs/testkey2.json";
    
    public static final String RESOLVER_BASE = "https://dev.uniresolver.io";
    public static final String RESOLVER = RESOLVER_BASE + "/1.0/identifiers/";
    
    public static LinkedHashMap loadJSON(String path) throws IOException {
        // create object mapper instance
        ObjectMapper mapper = new ObjectMapper();
        
        // convert JSON file to map
        Map<?, ?> map = mapper.readValue(Paths.get(path).toFile(), Map.class);
        final ArrayList<ArrayList> keys = (ArrayList) map.get("keys");
        
        for(int i = 0; i < keys.size(); i++) {
            
            final ArrayList entry = keys.get(i);
            
            final String keyName = (String) entry.get(0);
            final LinkedHashMap keyMetadata = (LinkedHashMap) entry.get(1);
            
            if(keyMetadata.get("type").equals("Ed25519VerificationKey2020")) {
                return keyMetadata;
            }
            
            for(Object key : keyMetadata.keySet()) {
                System.out.println(key + "=" + keyMetadata.get(key));
            }
        }
        return null;
    }
    
    public static Map<String, Object> generateDemoClaims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        Map<String, Object> degree = new LinkedHashMap<String, Object>();
        degree.put("name", "Bachelor of Science and Arts");
        degree.put("type", "BachelorDegree");
        claims.put("college", "Test University");
        claims.put("degree", degree);
        
        return claims;
    }
    
    public static VerifiableCredential createVC(String issuerDID, String subjectDID, Map<String, Object> credentialClaims) {
        CredentialSubject credentialSubject = CredentialSubject.builder()
                .id(URI.create(subjectDID))
                .claims(credentialClaims)
                .build();
        
        LocalDateTime now = LocalDateTime.now();
        
        
        VerifiableCredential verifiableCredential = VerifiableCredential.builder()
                .context(VerifiableCredentialContexts.JSONLD_CONTEXT_W3C_2018_CREDENTIALS_EXAMPLES_V1)
                .type("UniversityDegreeCredential")
                .id(URI.create("http://ssi.failing.systems/credentials/3732"))
                .issuer(URI.create(issuerDID))
                .issuanceDate(java.util.Date.from(now.atZone(ZoneId.systemDefault()).toInstant()))
                .expirationDate(java.util.Date.from(now.plusMonths(12).atZone(ZoneId.systemDefault()).toInstant()))
                .credentialSubject(credentialSubject)
                .build();
        
        return verifiableCredential;
    }
    
    public static VerifiableCredential signVC(VerifiableCredential verifiableCredential, String issuerKeyID, byte[] issuerPrivateKey) throws JsonLDException, GeneralSecurityException, IOException {
        System.out.println("Sign VC using key " + issuerKeyID);
        
        Ed25519Signature2020LdSigner signer = new Ed25519Signature2020LdSigner(issuerPrivateKey);
        signer.setCreated(new Date());
        signer.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_VERIFICATIONMETHOD);
        signer.setVerificationMethod(URI.create(issuerKeyID));
        signer.setDomain("failing.systems");
        signer.setNonce(UUID.randomUUID().toString());
        LdProof ldProof = signer.sign(verifiableCredential);
        
        return verifiableCredential;
    }
    
    public static byte[] resolveDidToPubkey(String did) throws ResolutionException {
        System.out.println("Resolving DID " + did + " ...");
        
        Map<String, Object> resolveOptions = new HashMap<>();
        resolveOptions.put("accept", "application/did+ld+json");
        
        ClientUniResolver uniResolver = new ClientUniResolver();
        uniResolver.setResolveUri(RESOLVER);
        
        // https://github.com/decentralized-identity/universal-resolver/blob/main/uni-resolver-core/src/main/java/uniresolver/result/ResolveRepresentationResult.java
        ResolveRepresentationResult resolveRepresentationResult = uniResolver.resolveRepresentation(did, resolveOptions);
        
        DIDDocument didDocument = resolveRepresentationResult.toResolveDataModelResult().getDidDocument();
        
        //System.out.println(didDocument.toJson(true));
        
        assertNotNull(didDocument);
        assertFalse(didDocument.getAuthenticationVerificationMethods().isEmpty());
        
        VerificationMethod authVerifyMethod = didDocument.getAuthenticationVerificationMethods().get(0);
        
        byte[] publicKeyBytes;
        switch(authVerifyMethod.getType()) {
            case "Ed25519VerificationKey2018":
                assertNotNull("Unsupported: Verification type is Ed25519VerificationKey2018, but encoding is not Base58.", authVerifyMethod.getPublicKeyBase58());
                final String publicKeyBase58 = authVerifyMethod.getPublicKeyBase58();
                return Base58.decode(publicKeyBase58);
            
            case "Ed25519VerificationKey2020":
                assertNotNull("Unsupported: Verification type is Ed25519VerificationKey2020, but encoding is not Multibase.", authVerifyMethod.getPublicKeyMultibase());
                final String publicKeyMultibase = authVerifyMethod.getPublicKeyMultibase();
                return decodeKey(publicKeyMultibase);
            
            default:
                fail("Invalid VerificationMethod type found in DID document: " + authVerifyMethod.getType());
        }
        
        return null;
    }
    
    public static byte[] decodeKey(String keyMultibase) {
        // decode multibase (e.g. base58btc)
        byte[] keyWithPrefix = Multibase.decode(keyMultibase);
        
        // remove ed25519-priv/-pub header (prefix) ...
        // https://github.com/digitalbazaar/ed25519-verification-key-2020/blob/main/lib/Ed25519VerificationKey2020.js#L12
        return Arrays.copyOfRange(keyWithPrefix, 2, keyWithPrefix.length);
    }
    
    @Test
    public void fullTest() throws IOException, JsonLDException, GeneralSecurityException, ResolutionException {
        // Issuer: load DID of issuer and subject (generated using nodejs helper)
        final LinkedHashMap issuerDidData = loadJSON(TESTKEY_ISSUER);
        final LinkedHashMap subjectDidData = loadJSON(TESTKEY_SUBJECT);
        
        String issuerDid = (String) issuerDidData.get("controller");
        String issuerKeyType = (String) issuerDidData.get("type");
        String issuerKeyID = (String) issuerDidData.get("id");
        String issuerPrivateKeyMultibase = (String) issuerDidData.get("privateKeyMultibase");
        String issuerPublicKeyMultibase = (String) issuerDidData.get("publicKeyMultibase");
        
        System.out.println("issuerDid: " + issuerDid);
        System.out.println("issuerKeyID: " + issuerKeyID);
        System.out.println("issuerKeyType: " + issuerKeyType);
        System.out.println("issuerPrivateKeyMultibase: " + issuerPrivateKeyMultibase);
        System.out.println("issuerPrivateKey base: " + Multibase.encoding(issuerPrivateKeyMultibase).toString());
        
        byte[] issuerPublicKey = decodeKey(issuerPublicKeyMultibase);
        byte[] issuerPrivateKey = decodeKey(issuerPrivateKeyMultibase);
        System.out.println("issuerPrivateKey length: " + issuerPrivateKey.length);
        
        String subjectDid = (String) subjectDidData.get("controller");
        
        // Issuer: create VC
        final Map<String, Object> demoClaims = generateDemoClaims();
        final VerifiableCredential vc = createVC(issuerDid, subjectDid, demoClaims);
        
        // Issuer: sign VC
        VerifiableCredential signedVC = signVC(vc, issuerKeyID, issuerPrivateKey);
        assertNotNull(signedVC);
        
        //System.out.println(signedVC.toJson(true));
        
        // Verifier: resolve DID from VC
        String issuerDidFromVC = signedVC.getIssuer().toString();
        byte[] discoveredPubkey = resolveDidToPubkey(issuerDidFromVC);
        
        assertArrayEquals(issuerPublicKey, discoveredPubkey);
        
        Ed25519Signature2020LdVerifier verifier = new Ed25519Signature2020LdVerifier(discoveredPubkey);
        
        // Verifier: verify VC
        boolean vcValid = verifier.verify(signedVC);
        
        assertTrue(vcValid);
    }
}
