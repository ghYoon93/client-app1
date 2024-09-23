package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.context.request.RequestContextListener;

/**
 * @주시스템 :   client-app
 * @서브 시스템        :   com.example.config
 * @프로그램 ID       :   ClientAppApplication
 * @프로그램 개요      :
 * @변경이력 ============================================================================
 * 1.0  2024. 09. 23.	:	yghee	-	신규생성
 * ============================================================================
 */
@SpringBootApplication
public class ClientAppApplication {

	public static void main ( String[] args ) {

		SpringApplication.run( ClientAppApplication.class );
	}

	@Bean
	public RequestContextListener requestContextListener() {
		return new RequestContextListener();
	}
}
