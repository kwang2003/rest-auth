package com.pachiraframework.token.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

import lombok.extern.slf4j.Slf4j;

import org.junit.Test;

@Slf4j
public class JwtTest {
	private static final String SECRET_KEY = "123456";
	@Test
	public void testJwt(){
		//为了掩饰，生成一个长生命周期的token，生产环境下sso操作时token的周期尽可能小
		long minutes = 5000000000000L;
		//5分钟token过期
		Date exp = new Date(System.currentTimeMillis()+minutes*60*1000);
	    String jwt = Jwts.builder()
	            .signWith(SignatureAlgorithm.HS256,SECRET_KEY)//SECRET_KEY是加密算法对应的密钥，这里使用额是HS256加密算法
	            .setExpiration(exp)
	            .setIssuer("kuaixian")
	            .setAudience("hp")
	            .claim("user_id","123")//该方法是在JWT中加入值为vaule的key字段
	            .claim("mobile","18512345678")
	            .claim("login_id", "admin")
	            .compact();
	    log.info(jwt);
	}
}
