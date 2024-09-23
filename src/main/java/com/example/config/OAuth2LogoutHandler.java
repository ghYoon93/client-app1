package com.example.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @주시스템 :   client-app
 * @서브 시스템        :   com.example.config
 * @프로그램 ID       :   OAuth2LogoutHandler
 * @프로그램 개요      :
 * @변경이력 ============================================================================
 * 1.0  2024. 09. 23.	:	yghee	-	신규생성
 * ============================================================================
 */
public class OAuth2LogoutHandler implements LogoutHandler {
	@Override
	public void logout( HttpServletRequest request, HttpServletResponse response,
						Authentication authentication ) {
		// OAuth2 제공자의 토큰 취소 엔드포인트 호출
	}
}
