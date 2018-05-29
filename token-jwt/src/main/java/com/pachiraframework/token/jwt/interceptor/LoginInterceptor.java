package com.pachiraframework.token.jwt.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.pachiraframework.token.jwt.SessionConstant;

/**
 * @author kevin wang
 *
 */
@Component
public class LoginInterceptor extends HandlerInterceptorAdapter {
	@Override
	public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object arg2,
			Exception exception) throws Exception {
	}
	
	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, Object arg2, ModelAndView arg3)
			throws Exception {
	}

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object arg2) throws Exception {
		// 获取Session
		HttpSession session = request.getSession(true);
		Long userId = (Long) session.getAttribute(SessionConstant.USER_ID);

		if (userId != null) {
			return true;
		}
		// 不符合条件的，跳转到登录界面
		request.getRequestDispatcher("/login").forward(request, response);
		return false;
	}
}
