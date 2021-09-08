package systems.failing.experiments;

import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2018LdVerifier;
import org.apache.commons.codec.DecoderException;
import org.bitcoinj.core.Base58;
import org.junit.Test;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.result.ResolveRepresentationResult;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class UniResolverTest {
    
    public static final String RESOLVER_BASE = "https://dev.uniresolver.io";
    public static final String RESOLVER = RESOLVER_BASE + "/1.0/identifiers/";
    
    private void resolveDid(String did) throws ResolutionException, DecoderException {
        Map<String, Object> resolveOptions = new HashMap<>();
        resolveOptions.put("accept", "application/did+ld+json");
        
        ClientUniResolver uniResolver = new ClientUniResolver();
        uniResolver.setResolveUri(RESOLVER);
        
        // https://github.com/decentralized-identity/universal-resolver/blob/main/uni-resolver-core/src/main/java/uniresolver/result/ResolveRepresentationResult.java
        ResolveRepresentationResult resolveRepresentationResult = uniResolver.resolveRepresentation(did, resolveOptions);
        
        
        System.out.println("Full Resolve Representation JSON:");
        System.out.println(resolveRepresentationResult.toJson());
        
        System.out.println("");
        System.out.println("DID Document JSON:");
        System.out.println(new String(resolveRepresentationResult.getDidDocumentStream(), StandardCharsets.UTF_8));
        
        final DIDDocument didDocument = resolveRepresentationResult.toResolveDataModelResult().getDidDocument();
        
        System.out.println("");
        System.out.println("DID Document:");
        System.out.println(didDocument.toJson(true));
        
        System.out.println("");
        System.out.println("DID Document, Authentication Methods:");
        
        if(!didDocument.getAuthenticationVerificationMethods().isEmpty()) {
            
            for(VerificationMethod verificationMethod : didDocument.getAuthenticationVerificationMethods()) {
                System.out.println(verificationMethod);
            }
            final VerificationMethod authVerifyMethod = didDocument.getAuthenticationVerificationMethods().get(0);
            
            System.out.println("");
            System.out.println("publicKeyType: " + authVerifyMethod.getType());
            
            final String publicKeyBase58 = authVerifyMethod.getPublicKeyBase58();
            System.out.println("publicKeyBase58: " + publicKeyBase58);
            if(publicKeyBase58 != null) {
                final byte[] publicKeyBytes = Base58.decode(publicKeyBase58);
                Ed25519Signature2018LdVerifier verifier = new Ed25519Signature2018LdVerifier(publicKeyBytes);
            }
            
            final String publicKeyHex = authVerifyMethod.getPublicKeyHex();
            System.out.println("publicKeyHex: " + publicKeyHex);
            // byte[] publicKeyBytes = Hex.decodeHex(publicKeyHex);
            
        } else {
            System.out.println("<not found in returned DID doc>");
        }
        
    }
    
    @Test
    public void didSovTest() throws ResolutionException, DecoderException {
        // example test from https://github.com/decentralized-identity/universal-resolver/blob/main/examples/src/main/java/uniresolver/examples/TestClientUniResolver.java
        
        resolveDid("did:sov:WRfXPg8dantKVubE3HX8pw");
    }
    
    @Test
    public void didKeyTest() throws ResolutionException, DecoderException {
        
        
        resolveDid("did:key:z6MkiB7DQAaJ1LaxUta6RuyyNYNLEomwoUaPzurruGg7dXPQ");
    }
}
