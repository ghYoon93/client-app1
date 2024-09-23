package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.web.servlet.config.annotation.*;

/**
 * @주시스템 :   client-app
 * @서브 시스템        :   com.example.config
 * @프로그램 ID       :   UiWebConfig
 * @프로그램 개요      :
 * @변경이력 ============================================================================
 * 1.0  2024. 09. 23.	:	yghee	-	신규생성
 * ============================================================================
 */
@Configuration
@EnableWebMvc
public class UiWebConfig implements WebMvcConfigurer {

	@Bean
	public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
		return new PropertySourcesPlaceholderConfigurer();
	}

	@Override
	public void configureDefaultServletHandling(final DefaultServletHandlerConfigurer configurer) {
		configurer.enable();
	}

	@Override
	public void addViewControllers(final ViewControllerRegistry registry) {
		registry.addViewController("/")
				.setViewName("forward:/index");
		registry.addViewController("/index");
		registry.addViewController("/securedPage");
	}

	@Override
	public void addResourceHandlers(final ResourceHandlerRegistry registry) {
		registry.addResourceHandler("/resources/**")
				.addResourceLocations("/resources/");
	}

}