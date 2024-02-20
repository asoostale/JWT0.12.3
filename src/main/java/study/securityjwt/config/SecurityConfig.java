package study.securityjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.securityjwt.jwt.JwtFilter;
import study.securityjwt.jwt.JwtUtil;
import study.securityjwt.jwt.LoginFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    private final AuthenticationConfiguration auditingConfiguration;
    private final JwtUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration auditingConfiguration, JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;

        this.auditingConfiguration = auditingConfiguration;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();

    }


    /**
     * 검증 할 떄는 비밀번호를 캐시로 암호화 시켜서 검증하고 진행
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder(); //메소드 구현 빈 등록
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {
        /**
         * csrf : Cross - Site Request Forgery(위조)
         * 사용자의 인증 정보를 이용해 사용자가 의도하지 않은 행위를 하게 만드는 공격 방법
         * 예를 들어, 사용자가 어떤 사이트에 로그인한 상태에서 악의적인 행동을 유도하는 링크나 버튼을 누르게 되면,
         * 해당 사이트는 사용자가 요청한 것으로 판단하게 됩니다.
         * 공격자는 이런 방식을 이용해 사용자의 권한으로 글을 작성하거나,
         * 정보를 변경하는 등의 행동을 하게 만들 수 있습니다.
         *
         * 이를 방지하기 위한 방법 중 하나는 CSRF 토큰을 사용하는 것입니다.
         * 이 토큰은 서버에서 생성하여 사용자의 세션에 저장하고, 동시에 사용자의 브라우저에도 전달합니다.
         * 사용자가 요청을 할 때, 이 CSRF 토큰을 함께 보내면 서버는 이를 검증하여 진짜 사용자의 요청인지 확인할 수 있습니다.
         * 이런 방식을 사용하면, 공격자가 이 CSRF 토큰값을 알지 못하므로 CSRF 공격을 방지할 수 있습니다.
         */

        /**
         * csrf - > disable
         * why? 세션방식에서는 항상 고정 고정이기에 필수적으로 방어해줘야 하는데
         * jwt는 세션을 session 을 stateless 상태로 관리하기에 csrf 의 공격을 방어하지 않아도 됨.
         */
        security.csrf((auth) -> auth.disable());

        //form 로그인 방식 사용 X
        security.formLogin((auth) -> auth.disable());
        //http basic 인증방식 사용 X
        security.httpBasic((auth) -> auth.disable());


        // 경로별 인가 작업
        security.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/login", "/", "/join").permitAll() // "login", "/", "/join"은 모든 권한 허용.
                .requestMatchers("/admin").hasRole("ADMIN") // "/admin "경로는 "ADMIN"만 접근 가능.
                .anyRequest().authenticated()); // 다른 요청에 대해서는 ✅Login 한 사용자만 접근 가능.✅

                                                //로그인 필터 앞에다가
        security.addFilterBefore(new JwtFilter(jwtUtil), LoginFilter.class);

        // .addFilterAt(대체할 필터 클래스, 위치)
        // **addFilterAt => 그 자리에 대체할 것이다!
        security.addFilterAt(new LoginFilter(authenticationManager(auditingConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);


        // ★★★★ 세션 설정 ★★★★ => STATELESS 상태로
        security.sessionManagement((session) ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return security.build(); //받은 인자를 build 타입으로 리턴
    }


}
