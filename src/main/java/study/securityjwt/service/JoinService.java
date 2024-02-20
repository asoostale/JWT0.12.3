package study.securityjwt.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import study.securityjwt.dto.JoinDto;
import study.securityjwt.entity.UserEntity;
import study.securityjwt.repository.UserRepository;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class JoinService {


    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;


    @Transactional
    public void joinProcess(JoinDto joinDto) {

        // 찾아서 존재한다면 회원가입 로직 진행 X => return ;으로 강제
        Boolean isExist = userRepository.existsByUsername(joinDto.getUsername());
        if (isExist) {
            return;
        }

        UserEntity user = new UserEntity();
        user.setUsername(joinDto.getUsername());
        /**
         * ★★★ 비밀번호는 바로 넣으면 안된다! ★★★
         * BcryptPasswordEncoder 주입 받아서 .encode 메소드로 암호화 진행
         */
        user.setPassword(encoder.encode(joinDto.getPassword()));
        user.setRole("ROEL_ADMIN");
        userRepository.save(user);
    }


}
