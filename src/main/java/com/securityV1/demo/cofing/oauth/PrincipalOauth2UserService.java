package com.securityV1.demo.cofing.oauth;

import com.securityV1.demo.cofing.auth.PrincipalDetails;
import com.securityV1.demo.cofing.oauth.provider.FaceBookUserInfo;
import com.securityV1.demo.cofing.oauth.provider.GoogleUserInfo;
import com.securityV1.demo.cofing.oauth.provider.OAUth2UserInfo;
import com.securityV1.demo.domain.User;
import com.securityV1.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * 타입이 DefaultOauth2UserService가 되어야 함
 */
@Service
@Slf4j
@RequiredArgsConstructor
@Lazy
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
//    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    private final UserRepository userRepository;

    /**
     * 이 메소드가 구글 로그인시 후처리 함수 -> 구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
     */
    // 함수가 종료될 때 @AuthenticationPrincipal 어노테이션이 만들어 진다.
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

        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("loadUser(userRequest).getAttributes = {}", oAuth2User.getAttributes());
        /**
         * getAttribute에서 정보를 얻을 수 있음 -> 이를 통해서 자동 회원가입 등등의 과정을 가져갈 수 있다.
         */

        OAUth2UserInfo oaUth2UserInfo = null;
        oaUth2UserInfo = getOaUth2UserInfo(userRequest, oAuth2User, oaUth2UserInfo);

        return getPrincipalDetails(oAuth2User, oaUth2UserInfo);
        //이 반환값이 Authentication안에 들어가게 됨 -> OAuth2User 로그인시 여기로 접근하여 Authentication에 들어가게 됨
    }

    private OAUth2UserInfo getOaUth2UserInfo(OAuth2UserRequest userRequest, OAuth2User oAuth2User, OAUth2UserInfo oaUth2UserInfo) {
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("구글 로그인 요청");
            oaUth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }

        if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            log.info("페이스북 로그인 요청");
            oaUth2UserInfo = new FaceBookUserInfo(oAuth2User.getAttributes());
        }
        return oaUth2UserInfo;
    }

    private PrincipalDetails getPrincipalDetails(OAuth2User oAuth2User, OAUth2UserInfo oaUth2UserInfo) {
        String provider = oaUth2UserInfo.getProvider();
        // google of facebook
        String providerId = oaUth2UserInfo.getProviderId();
        // 넘어오는 ProviderId
        String email = oaUth2UserInfo.getEmail();
        // email값
        String username = provider + "_" + providerId;
        // google_1032140005 이런식으로 생성됨
        String password = bCryptPasswordEncoder.encode("getInThere");
        // 아무 값이 넣어줌(필요없어서)
        String role = "ROLE_USER";

        Optional<User> userById = userRepository.findByUsername(username);

        if (userById.isEmpty()) {
            log.info("최초의 OAuth2 로그인");
            User user = User.builder()
                    .username(username)
                    .password(password)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .email(email)
                    .build();

            userRepository.save(user);
            return new PrincipalDetails(user, oAuth2User.getAttributes());
        }

        log.info("이미 존재하는 OAuth 아이디");
        return new PrincipalDetails(userById.get(), oAuth2User.getAttributes());
    }
}
