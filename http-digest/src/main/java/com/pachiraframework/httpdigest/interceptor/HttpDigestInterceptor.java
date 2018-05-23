package com.pachiraframework.httpdigest.interceptor;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.util.DigestUtils;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.github.kevinsawicki.http.HttpRequest.Base64;
import com.google.common.base.Function;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;

@Slf4j
@Component
public class HttpDigestInterceptor extends HandlerInterceptorAdapter {
    public static String SERVER_REALM = "serverrealm";
    public static String NONCE_KEY= "servernoncekey";
    public static int NONCE_VALIDITY_SECONDS = 30;
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
		// 从header中取Basic认证信息
		// Authorization: Basic YWRtaW46YWRtaW4=
		String auth = request.getHeader("Authorization");  
		log.info("auth:{}",auth);
		if(Strings.isNullOrEmpty(auth)){
			response.setStatus(401);
			String nonce = UUID.randomUUID().toString();
			response.addHeader("WWW-Authenticate", "Digest Realm=\"test\",qop=\"auth\",nonce=\""+nonce+"\",opaque=\"5ccc069c403ebaf9f0171e9517f40e41\",algorithm=MD5");
//			sendWWWAuthenticateDigestMessage(response);
			return false;
		}else{
			// 截取Basic 之后的字符
			String authInfo = auth.substring(7,auth.length());
			Map<String, String> authMap = parseDigestAuthorizationHeader(authInfo);
	        String username = authMap.get("username");
	        String realm = authMap.get("realm");
	        String nonce = authMap.get("nonce");
	        String uri = authMap.get("uri");
	        String resp = authMap.get("response");
	        String qop = authMap.get("qop");
	        String nc = authMap.get("nc");
			String cnonce = authMap.get("cnonce");
			
			
			String userPassword = new String(Base64Utils.decodeFromString(authInfo));
			log.info(userPassword);
			String[] strs = userPassword.split(":");
			if(passwordMatch(strs[0], strs[1])){
				return true;
			}
			return false;
		}
	}
    
	private Map<String, String> parseDigestAuthorizationHeader(String authorizationHeader){
		Map<String, String> map = Maps.newHashMap();
		Iterator<String> iterator = Splitter.on(',').split(authorizationHeader).iterator();
		while(iterator.hasNext()){
			String input = iterator.next();
			Iterator<String> it = Splitter.on('=').split(input).iterator();
			String key = it.next();
			String value = it.next();
			map.put(key.trim(), value.trim());
		}
		return map;
	}
	
	private boolean passwordMatch(String user,String password){
		if("admin".equals(user) && "123456".equals(password)){
			return true;
		}
		return false;
	}
	
}
