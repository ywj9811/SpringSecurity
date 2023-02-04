package com.securityV1.demo.service;

import com.securityV1.demo.domain.User;
import com.securityV1.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public User save(User user) {
        log.info("Service user = {}", user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);

        User save = userRepository.save(user);
        log.info("return = {}", save);
        return save;
    }

    public boolean login(String id, String pw) {
        return true;
    }
}
