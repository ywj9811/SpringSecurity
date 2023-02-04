package com.securityV1.demo.cofing.auth;

import com.securityV1.demo.domain.User;
import com.securityV1.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * 시큐리티 설정에서 .loginProcessingUrl("/login);이 있기 때문에
 * //login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어 있는 loadUserByUsername 함수가 실행된다.
 */
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    /**
     * 중요!! username이라는 파라미터로 받고 있는데, 만약 loginForm에서 name=username이 아닌 다른 것으로 보내게 되면 매칭이 안됨!!
     * 바꾸고 싶다면 config에서 .usernameParameter("이름") 이렇게 설정해야 한다
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> byUsername = userRepository.findByUsername(username);
        if (byUsername.isEmpty())
            return null;
        User user = byUsername.get();
        return new PrincipalDetails(user); // -> PrincipalDetails = userDetails 타입임

        /** 즉, 시큐리티 자체의 세션(Security ContextHolder)에는 Authentication 객체가 들어가야 하는데, Authentication객체에 넣어주는 정보는 UserDetails 타입이어야 한다.
         * 따라서 UserDetails를 implement 하여 만들어주면 사용할 수 있따.
         * 여기서 PrincipalDetails로 리턴을 했을 때 자동으로 Authentication객체로 되어
         * 자동으로 Security의 세션안에 Authentication객체로 들어가게 된다.
         * 자동!!
         * 그러면 로그인이 완료가 됨
         */
    }
}
