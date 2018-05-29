package com.pachiraframework.token.jwt.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.pachiraframework.token.jwt.SessionConstant;
import com.pachiraframework.token.jwt.model.UserInfo;
import com.pachiraframework.token.jwt.service.UserService;

/**
 * 首页
 * @author kevin wang
 *
 */
@Controller
public class IndexController {
	@Autowired
	private UserService userService;
	@RequestMapping(path= {"/","index"},method=RequestMethod.GET)
	public String index(HttpServletRequest request,Model model) {
		Long currentUserId = (Long) request.getSession(true).getAttribute(SessionConstant.USER_ID);
		UserInfo userInfo = userService.getById(currentUserId);
		model.addAttribute("userInfo", userInfo);
		return "index";
	}
}
