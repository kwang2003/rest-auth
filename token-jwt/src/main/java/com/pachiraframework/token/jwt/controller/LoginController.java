package com.pachiraframework.token.jwt.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.pachiraframework.token.jwt.SessionConstant;
import com.pachiraframework.token.jwt.model.UserInfo;
import com.pachiraframework.token.jwt.service.UserService;

/**
 * 正常登陆操作
 * @author kevin wang
 *
 */
@Controller
public class LoginController {
	@Autowired
	private UserService userService;
	@RequestMapping(path="/login",method=RequestMethod.POST)
	public String doLogin(HttpServletRequest request,HttpServletResponse response) {
		String loginId = request.getParameter("loginId");
		String password = request.getParameter("password");
		UserInfo userInfo = userService.doLogin(loginId, password);
		request.getSession(true).setAttribute(SessionConstant.USER_ID, userInfo.getUserId());
		request.getSession(true).setAttribute(SessionConstant.USER_NAME, userInfo.getName());
		return "redirect:/index";
	}
	
	@RequestMapping(path="/login",method=RequestMethod.GET)
	public String login() {
		return "login";
	}
	
	@RequestMapping(path="/logout",method=RequestMethod.GET)
	public String logout(HttpServletRequest request) {
		request.getSession().invalidate();
		return "login";
	}
}
