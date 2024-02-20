package study.securityjwt.jwt;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.securityjwt.dto.CustomUserDetail;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;


@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {


    // Dto를 얘한테 검증 받아야 한다.
    private final AuthenticationManager authenticationManager;

    private final JwtUtil jwtUtil;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("username = " + username);
        System.out.println("password = " + password);


        //username 과 password 를 담은 Dto 바구니
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(username, password, null);
                                                        // request.getParameter("username"),
                                                        // request.getParameter("password")
        return authenticationManager.authenticate(authToken);
    }

    //로그인 성공 시 실현되는 메소드
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        CustomUserDetail customUserDetail =(CustomUserDetail) authResult.getPrincipal();
        String username = customUserDetail.getUsername();
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String roll = auth.getAuthority();
        String token = jwtUtil.createJwt(username, roll, 60 * 60 * 10L);
        response.addHeader("Authorization", "Bearer " + token);
                                                  // 띄어쓰기 무조건


    }

    //로그인 실패시 실현 되는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

        response.setStatus(401);
    }
}
