package com.pachiraframework.token.jwt.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

import javax.servlet.http.HttpServletRequest;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import com.pachiraframework.token.jwt.SessionConstant;
import com.pachiraframework.token.jwt.model.UserInfo;
import com.pachiraframework.token.jwt.service.UserService;

/**
 * 其他系统通过sso进行登陆的额操作
 * @author kevin wang
 *
 */
@Slf4j
@Controller
@RequestMapping(path="/pc")
public class SSOCallbackController {
	//和SSO服务提供方约定的数据加密方式，不能泄漏
	private static final String SECRET_KEY = "123456";
	
	@Autowired
	private UserService userService;
	@RequestMapping(path="/sso_callback")
	public String callback(HttpServletRequest request) {
		//校验access_token的合法性，并从里面解析出有价值的数据（例如mobile字段）
		String accessToken = request.getParameter("access_token");
		try {
			String mobile = this.parseToken(accessToken);
			UserInfo userInfo = userService.getByMobile(mobile);
			//模拟登录过程
			request.getSession().setAttribute(SessionConstant.USER_ID, userInfo.getUserId());
			request.getSession().setAttribute(SessionConstant.USER_NAME, userInfo.getName());
		}catch (ExpiredJwtException e) {
			log.error("token已经过期");
		}catch(SignatureException e){
			log.error("签名错误");
		}
		
//		String redirectUril = request.getParameter("redirect_uri");
		String redirectUril = "http://localhost:8080/index";
		return "redirect:"+redirectUril;
	}
	
	private String parseToken(String jwt) {
		log.info("JWT:{}",jwt);
		//解析JWT字符串中的数据，并进行最基础的验证
        Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)//SECRET_KEY是加密算法对应的密钥，jjwt可以自动判断机密算法
                .parseClaimsJws(jwt)//jwt是JWT字符串
                .getBody();
        log.info("JWT CLAIMS:"+claims);
        //验证issuer和audience是否匹配
        return (String)claims.get("mobile");
	}
}
