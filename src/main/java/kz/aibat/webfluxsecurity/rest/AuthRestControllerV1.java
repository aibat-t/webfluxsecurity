package kz.aibat.webfluxsecurity.rest;

import kz.aibat.webfluxsecurity.dto.AuthRequestDto;
import kz.aibat.webfluxsecurity.dto.AuthResponseDto;
import kz.aibat.webfluxsecurity.dto.UserDto;
import kz.aibat.webfluxsecurity.entity.UserEntity;
import kz.aibat.webfluxsecurity.mapper.UserMapper;
import kz.aibat.webfluxsecurity.security.CustomPrincipal;
import kz.aibat.webfluxsecurity.security.SecurityService;
import kz.aibat.webfluxsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthRestControllerV1 {

    private final SecurityService securityService;
    private final UserService userService;
    private final UserMapper userMapper;

    @PostMapping("/register")
    public Mono<UserDto> register(@RequestBody UserDto dto) {
        UserEntity entity =  userMapper.map(dto);

        return userService.registerUser(entity)
                .map(userMapper::map);
    }

    @PostMapping("/login")
    public Mono<AuthResponseDto> login(@RequestBody AuthRequestDto dto) {
        return securityService.authenticate(dto.getUsername(), dto.getPassword())
                .flatMap(tokenDetails -> Mono.just(
                        AuthResponseDto.builder()
                                .userId(tokenDetails.getUserId())
                                .token(tokenDetails.getToken())
                                .issuedAt(tokenDetails.getIssuedAt())
                                .expiresAt(tokenDetails.getExpiresAt())
                                .build()
                ));

    }

    @GetMapping("/info")
    public Mono<UserDto> getUserInfo(Authentication authentication) {
        CustomPrincipal principal = (CustomPrincipal) authentication.getPrincipal();

        return userService.getUserById(principal.getId())
                .map(userMapper::map);
    }
}
