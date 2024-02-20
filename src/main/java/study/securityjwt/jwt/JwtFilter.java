package study.securityjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import study.securityjwt.dto.CustomUserDetail;
import study.securityjwt.entity.UserEntity;

import java.io.IOException;


@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {


    private final JwtUtil jwtUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //request에서 Authorization 헤더를 찾음
        String authorization = request.getHeader("Authorization");

        //토큰이 담겼는지
        if (authorization == null || authorization.startsWith("Bearer ")) {
            System.out.println("token null");
            filterChain.doFilter(request, response);

            //조건이 해당되면(토큰 있으면) 메서드 종료(필수)
            return ;
        }

        System.out.println("authorization now");
        //Bear 부분 제거 순수 토큰만 확인
        String token = authorization.split(" ")[1]; // 앞부분 있고 뒷부분 있는데 뒷부분이 두번째 인덱스

        //토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);
         // 조건이 해당되면 메서드 종료
            return;
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        //userEntity를 생성하여 값 set
        UserEntity entity = new UserEntity();
        entity.setUsername(username);
        entity.setPassword("temppassword");
        entity.setRole(role);

        // userDetails에 회원 정보 객체 담기
        CustomUserDetail customUserDetail = new CustomUserDetail(entity);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authenticationToken = new UsernamePasswordAuthenticationToken(
                customUserDetail,
                null,
                customUserDetail.getAuthorities());


        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request, response);
    }

}

