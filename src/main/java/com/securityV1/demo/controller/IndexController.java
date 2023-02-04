package com.securityV1.demo.controller;

import com.securityV1.demo.cofing.auth.PrincipalDetails;
import com.securityV1.demo.domain.User;
import com.securityV1.demo.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller //View 리턴
@RequiredArgsConstructor
@Slf4j
public class IndexController {
    private final UserService userService;


    @ResponseBody
    @GetMapping("/test/login")
    public String loginTest(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) {
        //이렇게 Authentication으로 받아서 UserDetails로 다운 캐스팅 혹은 @AuthenticationPrincipal이라는 어노테인션을 사용하여 UserDetails타입으로 받아 사용할 수 있다.
        //UserDetails를 PrincipalDetails가 상속받기 때문에 PrincipalDetails도 가능함 -> 내가 원하는 용도로 만들었으니 사용
        
        log.info("/test/login --------------------------");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.info("authentication : {}", principalDetails.getUser());

        log.info("userDetails.getUsername : {}", userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @ResponseBody
    @GetMapping("/test/oauth/login")
    public String loginOAuthTest(Authentication authentication, @AuthenticationPrincipal OAuth2User oauth) {
        //OAuth2를 사용하게 되면 PrincipalDetails를 사용하는 것이 아닌 Oauth2User타입으로 받아서 사용해야 함
        //이를 통해서 제공받은 정보를 확인할 수 있음

        //시큐리티 세션에 들어갈 수 있는 Authentication객체에는 UserDetails혹은 OAuth2User타입만 들어갈 수 있다.
        //일반 로그인 -> UserDetails
        //OAuth2 로그인 -> OAuth2User

        //그럼 어떻게 할까 -> UserDetails와 OAuth2User를 implement하는 객체를 하나 만들어서 사용

        log.info("/test/login --------------------------");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.info("authentication : {}", oAuth2User.getAttributes());

        log.info("authentication : {}", oauth.getAttributes());

        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"", "/"})
    public String index() {
        return "index";
        // /src/main/resources/template/index.mustache를 찾아감 (기본)
        // 따라서 이것을 html으로 바꾸기 위해서 config 작성함 : viewResolver 재설정함
    }
    /**
     * 이번에는 jsp, thymeleaf 가 아닌 머스테치를 사용할 것
     * 머시테치 기본 폴더 : src/main/resources/
     * 뷰 리졸버 설정 : templates(prefix), .mustache(suffix)
     * 이것이 기본 설정
     */
    /**
     * 기본적으로 그냥 시작하게 되면 페이지가 뜨는 것이 아닌, login페이지가 나오게 된다.
     * 이는 security가 발급하는 인증번호를 통해서 입장할 수 있게 되는 것이다.
     * 이는 SecurityConfig 파일을 생성하면서 안뜨게 된다.
     * 접근이 걍 안됨ㅋㅋ
     * 다른 부분에서 처리해주자
     * .and()
     * .formLogin()
     * .loginPage("/login"); 이제 기존의 디폴트 /login은 사용되지 않고 우리의 login.html이 사용될 것이다.
     * 이를 통해서 로그인이 필요한 경우 어떤 페이지로 이동시킬지 정할 수 있다. (이로써 커스텀 하는 것이다.)
     * 그러면 이제 아래 3개의 경로로 접근하면 /login으로 이동되게 된다.
     */
    /**
     * WebConfig 설정한 이후
     * user, manager, admin은 권한 혹은 인증이 필요하게 해둠
     * 따라서 경로에서 "/"는 문제없으나 /user, /admin, /manager는 못들어간다. 인증 혹은 권한 필요
     */

    @GetMapping("/user")
    @ResponseBody
    public String user() {
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public void joinForm() {
        return;
    }

    @PostMapping("/join")
    public String join(User user) {
        log.info("user = {}", user);
        User save = userService.save(user);
        log.info("Fin user = {}", save);
        return "redirect:/loginForm";
    }

    @GetMapping("/info")
    @Secured("ROLE_ADMIN")
    //이 접근에는 ROLE_ADMIN권한이 필요함을 선언함 -> Config에서 @EnableGlobalMethodSecurity(securedEnabled = true)  이것을 통해서 켜놓았기 때문임
    @ResponseBody
    public String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    //@Secured과 다르게 여러종류의 권한을 걸기 위해서는 @PreAuthorize를 사용할 수 있는데
    // 이는 hasRole을 사용하며 Config에서 @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnable = true) 설정을 해주어서 가능하게 된다.
    @GetMapping("/data")
    @ResponseBody
    public String data() {
        return "데이타";
    }
}
