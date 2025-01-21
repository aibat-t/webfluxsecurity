package kz.aibat.webfluxsecurity.service;

import kz.aibat.webfluxsecurity.entity.UserEntity;
import kz.aibat.webfluxsecurity.entity.UserRole;
import kz.aibat.webfluxsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Mono<UserEntity> registerUser(UserEntity user) {
        return userRepository.save(
                user.toBuilder()
                        .password(passwordEncoder.encode(user.getPassword()))
                        .role(UserRole.USER)
                        .enabled(true)
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .build()
        ).doOnSuccess(u -> {
            log.info("IN register user {}", u);
        });
    }

    public Mono<UserEntity> getUserById(Long id) {
        return userRepository.findById(id);
    }

    public Mono<UserEntity> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
