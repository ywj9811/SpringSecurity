package com.securityV1.demo.cofing;

import com.securityV1.demo.cofing.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity //활성화 시키는 것이다 : Spring Security 필터(설정하는 Config)가 Spring 필터 체인에 등록이 된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //@Secured어노테이션 활성화(각각에서 권한을 설정할 수 있다)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PrincipalOauth2UserService principalOauth2UserService;

    //해당 메소드의 리턴되는 메소드를 IoC로 등록(@Bean이 있으니까)
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable(); //csrf 비활성화
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // /user/**의 경로는 인증이 필요하다! (로그인 필요)
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") //인증 + 특별한 권한 필요
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll() //위 3가지가 아닌 나머지 모든 요청은 권한, 인증 필요없다.
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") //login주소가 호출되면 시큐리티가 낚아채서 진행하게 된다.
                .defaultSuccessUrl("/")
                //권한이 없는 경우 로그인 페이지로 이동 할 것인데, .loginPage()를 통해서 어떤 페이지로 이동할지 지정
                .and()
                .oauth2Login()//oath2Login을 통해 로그인을 할 수 있도록 해줌 이부분은 google혹은 facebook 등등에서 설정 (oauth2/authorization/어떤로그인) 이 경로로 설정 -> 고정 경로임
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService); //구글 로그인이 완료된 뒤의 후처리가 필요함 -> 이 service에서 후처리 (loadUser라는 메소드)
                /**1. 코드받기(인증)
                 * 2. 엑세스토큰(권한)
                 * 3. 사용자 프로필정보 가져옴
                 * 4. 그 정보를 토대로 회원가입 자동으로 진행시키기도 함
                 *   이때 그 정보가 부족하다면 추가적으로 정보를 받아서 회원가입 시키기도 함
                 *
                 * Tip : 구글 로그인이 완료되면 엑세스 토큰 + 사용자 프로필 정보 동시에 받아옴
                 */
    }
}
/**
 * 권한에 따라서 접근을 할 수 있도록 설정을 하자
 */
