package com.pachiraframework.appkeysign.controller;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.TreeSet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.collect.Maps;
import com.google.common.hash.Hashing;

/**
 * @author kevin wang
 * 
 */
@Slf4j
@RestController
public class DemoController {
	@RequestMapping(path = "/demo.json", method = RequestMethod.GET)
	public String auth(HttpServletRequest request, HttpServletResponse response) throws UnsupportedEncodingException {
		TreeSet<String> params = new TreeSet<String>();
		params.add("timestamp");
		params.add("name");
		params.add("appkey");
		params.add("channel");
		StringBuffer buffer = new StringBuffer();
		for(String param : params){
			buffer.append(param);
			buffer.append(request.getParameter(param));
		}
		log.info("{}",buffer);
		String encoded = new String(buffer.toString().getBytes("UTF-8"));
		String appkey = request.getParameter("appkey");
		String secret = appkeySecret().get(appkey);
		String input = new StringBuffer(secret).append(encoded).append(secret).toString();
		String newSign = Hashing.md5().hashString(input, Charset.defaultCharset()).toString();
		log.info("new sign :{}",newSign);
		
		//验证是否已经过期，防止重放
		Long timestamp = Long.valueOf(request.getParameter("timestamp"));
		long now = System.currentTimeMillis();
		if(now-timestamp > 10*60*1000L){//超过10分钟
			log.warn("该请求已经过期");
			//return "请求过期";
		}
		//签名匹配校验
		String sign = request.getParameter("sign");
		if(sign.equals(newSign)){
			//请求合法
			return "demo";
		}
		return "error";
	}

	private Map<String, String> appkeySecret() {
		Map<String, String> map = Maps.newHashMap();
		map.put("appkey1", "secret1");
		map.put("appkey2", "secret2");
		return map;
	}
}
