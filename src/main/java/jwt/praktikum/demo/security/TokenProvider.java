package jwt.praktikum.demo.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider {

    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private final long tokenValidateMilliseconds;
    private final long tokenValidateMillisecondRemember;

    private static final String AUTHORITIES_KEY = "auth";

    private final Key key;

    private final JwtParser jwtParser;

    public TokenProvider() {
        byte[] keyByte;
        String secret = "SmF4b25naXJfQ29ycG9yYXRpb25fVEVTVF9KQVZBXzExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMQ==";
        keyByte = Decoders.BASE64.decode(secret);
        key = Keys.hmacShaKeyFor(keyByte);
        jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
        tokenValidateMillisecondRemember = 1000 * 86400;
        tokenValidateMilliseconds = 1000 * 3600;
    }

    public boolean validateToken(String jwt) {
        try {
            jwtParser.parseClaimsJws(jwt);
            return true;
        } catch (ExpiredJwtException e) {
            logger.error("Token is expired");
        } catch (UnsupportedJwtException e) {
            logger.error("Token is unsupported");
        } catch (MalformedJwtException e) {
            logger.error("Token is malformed");
        } catch (SignatureException e) {
            logger.error("Token is Signature");
        } catch (IllegalArgumentException e) {
            logger.error("Token is IllegalArgument");
        }
        return false;

    }
    public Authentication getAuthentication(String jwt) {
    Claims claims = jwtParser.parseClaimsJws(jwt).getBody();
        Collection<? extends GrantedAuthority> authorities = Arrays
                .stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .filter(auth -> !auth.trim().isEmpty())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        User principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, jwt, authorities);
    }
    public String createToken(Authentication authentication, boolean rememberMe) {

        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));


        long now = (new Date()).getTime();
        Date validate;
        if (rememberMe) {
            validate = new Date(now + tokenValidateMillisecondRemember);
        } else {
            validate = new Date(now + tokenValidateMilliseconds);
        }
        return Jwts
                .builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validate)
                .compact();
    }


}
