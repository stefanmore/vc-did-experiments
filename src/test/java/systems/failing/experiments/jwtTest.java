package systems.failing.experiments;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.Test;

import java.security.Key;

import static org.junit.Assert.assertTrue;

public class jwtTest {
    
    @Test
    public void quickstartTest() {
        //via https://github.com/jwtk/jjwt#quickstart
        
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256); // --> use other algorithms here (e.g. asymmetric!)
        String jws = Jwts.builder().setSubject("Joe").signWith(key).compact();
        
        System.out.println(jws); // --> inspect using e.g. https://jwt.io/
        
        assertTrue(Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jws).getBody().getSubject().equals("Joe"));
        
    }
    
}
