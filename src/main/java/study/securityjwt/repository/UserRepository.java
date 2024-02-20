package study.securityjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.securityjwt.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    Boolean existsByUsername(String username);


    UserEntity findByUsername(String username);

}
