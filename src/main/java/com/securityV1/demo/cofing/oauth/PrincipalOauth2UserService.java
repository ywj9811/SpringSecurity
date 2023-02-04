package com.securityV1.demo.cofing.oauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

/**
 * 타입이 DefaultOauth2UserService가 되어야 함
 */
@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    /**
     * 이 메소드가 구글 로그인시 후처리 함수 -> 구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest.getClientRegistration = {}", userRequest.getClientRegistration());
        /**
         * registrationId를 통해 어떤 OAuth로 로그인 하였는지 확인 가능
         */

        log.info("userRequest.getAccessToken.getTokenValue = {}", userRequest.getAccessToken().getTokenValue());
        /**
         * 구글 로그인 버튼 클릭시 -> 구글 로그인 창 -> 로그인 완료 -> code 반환 (OAuth-Client 라이브러리) -> AccessToken 요청
         * : userRequest 정보를 얻음
         * userRequest 정보 -> 회원 프로필 받아야함 (loadUser함수) -> 회원 프로필 받음
         */

        log.info("loadUser(userRequest).getAttributes = {}", super.loadUser(userRequest).getAttributes());
        /**
         * getAttribute에서 정보를 얻을 수 있음 -> 이를 통해서 자동 회원가입 등등의 과정을 가져갈 수 있다.
         */

        OAuth2User oAuth2User = super.loadUser(userRequest);
        return super.loadUser(userRequest);
    }
}
