package study.securityjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static io.jsonwebtoken.Jwts.claims;

/**
 * 구현 메소드
 *  1. JWTUtil 생성자
 *  2. username 확인 메소드
 *  3. role 확인 메소드
 *  4. 만료일 확인 메소드
 */

@Component
public class JwtUtil {

    private SecretKey secretKey;

                    //yml에 생성한 암호화
    public JwtUtil(@Value("${spring.jwt.secret}") String secret) {

        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm()); {
        }
    }

    public String getUsername(String token) {
                            //검증 진행
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
                //토큰이 우리 서버에서 생성되었는지, 그게 우리가 가지고 있는 key와 맞는

    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    // 토큰이 소멸 되었는지
    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
                                                                                                            //현재 시간값을 넣어줘야 소멸인지 확인가능
    }

    // 토큰 생성
    public String createJwt(String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("username", username)  // .claim : 선언
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))  // 언제 발행 됐는지 : 현재 발행 시간 넣어줄 수 있음
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 언제 소멸 할 것인지
                .signWith(secretKey) // 사인해라
                .compact(); // 발행

    }
}
