package com.pachiraframework.httpbasic.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.google.common.base.Strings;

@Slf4j
@Component
public class HttpBasicInterceptor extends HandlerInterceptorAdapter {
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
		// 从header中取Basic认证信息
		// Authorization: Basic YWRtaW46YWRtaW4=
		String auth = request.getHeader("Authorization");  
		log.info("auth:{}",auth);
		if(Strings.isNullOrEmpty(auth)){
			response.setStatus(401);
			response.addHeader("WWW-Authenticate", "Basic Realm=\"test\"");
			return false;
		}else{
			// 截取Basic 之后的字符
			String authInfo = auth.substring(6,auth.length());
			String userPassword = new String(Base64Utils.decodeFromString(authInfo));
			log.info(userPassword);
			String[] strs = userPassword.split(":");
			if(passwordMatch(strs[0], strs[1])){
				return true;
			}
			return false;
		}
	}
	
	private boolean passwordMatch(String user,String password){
		if("admin".equals(user) && "123456".equals(password)){
			return true;
		}
		return false;
	}
}
