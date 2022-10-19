package com.cos.securityex01.config.oauth;

import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.securityex01.config.auth.PrincipalDetails;
import com.cos.securityex01.config.oauth.provider.FaceBookUserInfo;
import com.cos.securityex01.config.oauth.provider.GoogleUserInfo;
import com.cos.securityex01.config.oauth.provider.NaverUserInfo;
import com.cos.securityex01.config.oauth.provider.OAuth2UserInfo;
import com.cos.securityex01.model.User;
import com.cos.securityex01.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

	@Autowired
	private UserRepository userRepository;

	// 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		// userRequest 는 code를 받아서 accessToken으로 사용자 정보까지 응답 받은 객체

		// code를 통해 구성한 정보
		System.out.println("userRequest : \n" + userRequest + '\n');
		System.out.println("userRequest clientRegistration : \n" + userRequest.getClientRegistration() + '\n');
		System.out.println("userRequest accessToken : \n" + userRequest.getAccessToken() + '\n');

		// token을 통해 응답받은 회원정보
		OAuth2User oAuth2User = super.loadUser(userRequest); // google의 회원 프로필 조회
		System.out.println("super.loadUser(userRequest) : \n" + oAuth2User + '\n');

		return processOAuth2User(userRequest, oAuth2User);
	}

	private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {

		// Attribute를 파싱해서 공통 객체로 묶는다. 관리가 편함.
		OAuth2UserInfo oAuth2UserInfo = null;
		if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			System.out.println("구글 로그인 요청~~");
			oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
		} else {
			System.out.println("우리는 구글만 지원해요 ㅎㅎ");
		}

		// 자동 회원가입
		Optional<User> userOptional =
				userRepository.findByProviderAndProviderId(oAuth2UserInfo.getProvider(), oAuth2UserInfo.getProviderId());

		User user;
		if (userOptional.isPresent()) { // user가 존재하면 update 해주기
			user = userOptional.get();
			user.setEmail(oAuth2UserInfo.getEmail());
			userRepository.save(user);
		} else { // user의 패스워드가 null이기 때문에 OAuth 유저는 일반적인 로그인을 할 수 없음.
			user = User.builder()
					.username(oAuth2UserInfo.getProvider() + "_" + oAuth2UserInfo.getProviderId())
					.email(oAuth2UserInfo.getEmail())
					.role("ROLE_USER")
					.provider(oAuth2UserInfo.getProvider()) // google
					.providerId(oAuth2UserInfo.getProviderId()) // google id
					.build();
			userRepository.save(user);
		}

		return new PrincipalDetails(user, oAuth2User.getAttributes());
	}
}
