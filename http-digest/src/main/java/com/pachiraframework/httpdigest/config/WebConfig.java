package com.pachiraframework.httpdigest.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import com.pachiraframework.httpdigest.interceptor.HttpDigestInterceptor;

@Configuration
public class WebConfig extends WebMvcConfigurerAdapter {
	@Autowired
	private HttpDigestInterceptor httpDigestInterceptor;
	@Override
	public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(httpDigestInterceptor);
    }
}
