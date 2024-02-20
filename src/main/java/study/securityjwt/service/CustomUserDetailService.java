package study.securityjwt.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import study.securityjwt.dto.CustomUserDetail;
import study.securityjwt.entity.UserEntity;
import study.securityjwt.repository.UserRepository;


@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {


        private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity findUser = userRepository.findByUsername(username);
        if (findUser != null) {
            return new CustomUserDetail(findUser);
        }

        return null;
    }
}
