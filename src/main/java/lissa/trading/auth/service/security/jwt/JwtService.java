package lissa.trading.auth.service.security.jwt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import lissa.trading.auth.service.details.CustomUserDetails;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lissa.trading.auth.service.dto.UserInfoDto;
import lissa.trading.auth.service.exception.EncryptionTokenException;
import lissa.trading.auth.service.service.EncryptionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.security.core.GrantedAuthority;

import java.security.Key;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtService {

    private final EncryptionService encryptionService;

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS256;

    @Value("${security.jwt.secret}")
    private String jwtSecret;

    @Value("${security.jwt.expiration}")
    private int jwtExpirationMs;

    @Value("${security.jwt.refreshExpiration}")
    private int jwtRefreshExpirationMs;

    private Key key;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostConstruct
    private void init() {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String generateJwtToken(Authentication authentication) {
        CustomUserDetails userPrincipal = (CustomUserDetails) authentication.getPrincipal();

        List<String> roles = userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Jwts.builder()
                .setSubject(userPrincipal.getTelegramNickname())
                .claim("firstName", userPrincipal.getFirstName())
                .claim("lastName", userPrincipal.getLastName())
                .claim("telegramNickname", userPrincipal.getTelegramNickname())
                .claim("tinkoffToken", userPrincipal.getTinkoffToken())
                .claim("roles", roles)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(key, SIGNATURE_ALGORITHM)
                .compact();
    }

    public String generateRefreshToken(Authentication authentication) {
        CustomUserDetails userPrincipal = (CustomUserDetails) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(userPrincipal.getTelegramNickname())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtRefreshExpirationMs))
                .signWith(key, SIGNATURE_ALGORITHM)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public List<String> getRolesFromJwtToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(validateAuthorizationHeader(token))
                .getBody();

        return objectMapper.convertValue(claims.get("roles"), new TypeReference<List<String>>() {
        });
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(validateAuthorizationHeader(authToken));
            return true;
        } catch (JwtException e) {
            log.error("JWT validation error: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public UserInfoDto getUserInfoFromJwtToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(validateAuthorizationHeader(token))
                .getBody();

        String encryptedTinkoffToken = null;
        try {
            encryptedTinkoffToken = encryptionService.encrypt(claims.get("tinkoffToken", String.class));
        } catch (Exception e) {
            log.error("Error encrypting Tinkoff token", e);
            throw new EncryptionTokenException("Could not encrypt Tinkoff token");
        }

        return UserInfoDto.builder()
                .firstName(claims.get("firstName", String.class))
                .lastName(claims.get("lastName", String.class))
                .telegramNickname(claims.get("telegramNickname", String.class))
                .tinkoffToken(encryptedTinkoffToken)
                .role(objectMapper.convertValue(claims.get("roles"), new TypeReference<List<String>>() {
                }))
                .build();
    }

    private String validateAuthorizationHeader(String authorizationHeader) {
        return authorizationHeader.startsWith("Bearer ") ? authorizationHeader.substring(7) : authorizationHeader;
    }
}