package com.pachiraframework.httpdigest.interceptor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import com.google.common.hash.Hashing;
import com.google.common.io.CharStreams;

/**
 * 实现<a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a> 的
 * <a href="https://zh.wikipedia.org/w/index.php?title=HTTP%E6%91%98%E8%A6%81%E8%AE%A4%E8%AF%81&action=edit&section=1s">HTTP摘要认证</a>
 * @author Kevin Wang
 *
 */
@Slf4j
@Component
public class HttpDigestInterceptor extends HandlerInterceptorAdapter {
    public static String SERVER_REALM = "serverrealm";
    public static String NONCE_KEY= "servernoncekey";
    public static int NONCE_VALIDITY_SECONDS = 30;
    private static final String REALM = "testrealm@host.com";
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse httpServletResponse, Object handler) throws Exception {
		String auth = request.getHeader("Authorization");  
		log.info("auth:{}",auth);
		if(Strings.isNullOrEmpty(auth)){
			httpServletResponse.setStatus(401);
			String nonce = UUID.randomUUID().toString();
			String opaque = UUID.randomUUID().toString();
			httpServletResponse.addHeader("WWW-Authenticate", "Digest Realm=\""+REALM+"\",qop=\"auth\",nonce=\""+nonce+"\",opaque=\""+opaque+"\"");
//			sendWWWAuthenticateDigestMessage(response);
			return false;
		}else{
			// 截取Basic 之后的字符
			String authInfo = auth.substring(7,auth.length());
			Map<String, String> authMap = parseDigestAuthorizationHeader(authInfo);
	        String username = authMap.get("username");
	        String realm = authMap.get("realm");
	        String nonce = authMap.get("nonce");
//	        String uri = authMap.get("uri");
	        String resp = authMap.get("response");
	        String qop = authMap.get("qop");
	        String nc = authMap.get("nc");
			String cnonce = authMap.get("cnonce");
			
			if(!realm.equals(REALM)){
				return false;
			}
			
			boolean userExist = this.userMap().containsKey(username);
			if(!userExist){
				log.info("用户{}不存在",username);
				return false;
			}
			
			String ha1 = Hashing.md5().hashString(username+":"+REALM+":"+this.userMap().get(username), Charset.defaultCharset()).toString();
			String ha2 = null;
			if(Strings.isNullOrEmpty(qop)||"auth".equals(qop)){
				//HA2 = MD5(A2)=MD5(method:uri)
				ha2 = Hashing.md5().hashString(request.getMethod()+":"+request.getRequestURI(), Charset.defaultCharset()).toString();
			}else if("auth-int".equals(qop)){
				// HA2=MD5(A2)=MD5(method:digestURI:MD5(entiryBody))
				BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream()));
				String body = CharStreams.toString(reader);
				String bodyMd5 = Hashing.md5().hashString(body,Charset.defaultCharset()).toString();
				ha2 = Hashing.md5().hashString(request.getMethod()+":"+request.getRequestURI()+":"+bodyMd5, Charset.defaultCharset()).toString();
			}
			String response = null;
			if(Strings.isNullOrEmpty(qop)){
				//response=MD5(HA1:nonce:HA2)
				response = Hashing.md5().hashString(ha1+":"+nonce+":"+ha2,Charset.defaultCharset()).toString();
			}else if("auth".equals(qop)||"auth-int".endsWith(qop)){
				//response=MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)
				response = Hashing.md5().hashString(ha1+":"+nonce+":"+nc+":"+cnonce+":"+qop+":"+ha2,Charset.defaultCharset()).toString();
			}
			log.info("response:{}",response);
			if(response.equals(resp)){
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
			if(!Strings.isNullOrEmpty(value)){
				if(value.startsWith("\"")){
					value = value.substring(1,value.length());
				}
				if(value.endsWith("\"")){
					value = value.substring(0,value.length()-1);
				}
			}
			map.put(key.trim(), value.trim());
		}
		return map;
	}
	
	
	private Map<String, String> userMap(){
		Map<String, String> map = Maps.newHashMap();
		map.put("admin", "123456");
		return map;
	}
}
