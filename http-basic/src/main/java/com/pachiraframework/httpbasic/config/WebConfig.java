package com.pachiraframework.httpbasic.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import com.pachiraframework.httpbasic.interceptor.HttpBasicInterceptor;

@Configuration
public class WebConfig extends WebMvcConfigurerAdapter {
	@Autowired
	private HttpBasicInterceptor httpBasicInterceptor;
	@Override
	public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(httpBasicInterceptor);
    }
}
