package com.example.config;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @주시스템 :   client-app
 * @서브 시스템        :   com.example.config
 * @프로그램 ID       :   UiSecurityConfig
 * @프로그램 개요      :
 * @변경이력 ============================================================================
 * 1.0  2024. 09. 23.	:	yghee	-	신규생성
 * ============================================================================
 */
@Configuration
@EnableOAuth2Sso // OAuth 2.0을 사용한 Single Sign-On(SSO)을 활성화합니다.
public class UiSecurityConfig extends WebSecurityConfigurerAdapter {

	public void configure(HttpSecurity http) throws Exception {

		http.antMatcher( "/**" ) // 모든 요청에 이 구성 적용
				.authorizeRequests() // 요청에 대한 인증 규칙 정의
				.antMatchers( "/", "/login**" )
				.permitAll() // 루트와 로그인 관련 경로는 인증 규칙에서 제외
				.anyRequest()
				.authenticated()  // 그외 모든 요청에 대해서 인증이 필요
				.and()
				.logout()
				.logoutSuccessUrl("/")
				.addLogoutHandler( new OAuth2LogoutHandler() )
				.logoutSuccessHandler((request, response, authentication) ->
						response.sendRedirect("http://sso.abc.com:8081/auth/logout" ) )
				.invalidateHttpSession(true)
				.permitAll();
	}

}