package com.securityV1.demo.cofing.auth;

import com.securityV1.demo.domain.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * 시큐리티가 /login주소 요청이 오면 낚아채서 로그인을 진행시킴
 * 로그인 진행이 완료되면 시큐리티 session을 만들어줘야 한다. (Security ContextHolder)
 * 이 Security ContextHolder에는 Authentication타입의 객체가 들어가야 한다.
 * Authentication타입의 객체 안에는 User의 정보가 들어가있어야 한다.
 * 이 때 User정보의 오브젝트 타입은 UserDetails타입 객체가 들어가야 한다.
 *
 * 즉, 시큐리티 자체의 세션(Security ContextHolder)에는 Authentication 객체가 들어가야 하는데, Authentication객체에 넣어주는 정보는 UserDetails 타입이어야 한다.
 * 따라서 UserDetails를 implement 하여 만들어주면 사용할 수 있따.
 */
@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {
    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    @Override
    public <A> A getAttribute(String name) {
        return OAuth2User.super.getAttribute(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        //해당 유저의 권한을 리턴하는 것이다.
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        /**
         * 예를 들어서 휴먼 계정의 경우 false를 반환하는 것이다.
         */
        return true;
    }
}
