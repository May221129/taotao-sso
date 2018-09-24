package com.taotao.sso.interceptor;

import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.taotao.common.annotation.IgnoreCheckoutToken;
import com.taotao.common.bean.RedisKeyConstant;
import com.taotao.common.util.CookieUtils;
import com.taotao.sso.bean.User;

/**
 * 拦截器：将所有需要做token校验的请求都拦截下来，在这里统一做token校验、Redis中token的生成时间的更新、返回Redis中存储的User信息。
 */
public class CheckoutInterceptor implements HandlerInterceptor {

	@Autowired
	private StringRedisTemplate stringRedisTemplate;// 用于操作Redis

	private static final String COOKIE_TOKEN = "TAOTAO_TOKEN";// cookie中token的key

	private static final long REDIS_SECONDS = 60 * 30;// token放入Redis后的存活时间，单位：秒

	private static final ObjectMapper MEPPER = new ObjectMapper();// 用于序列化和反序列化

	private static final String USER_FROM_REDIS = "USER_FROM_REDIS";// 从Redis中通过token获取的User对象

	private static final int TOKEN_FROM_COOKIE_SECONDS = 60 * 30;// cookie中token的存活时长：30分钟
	
	/**
	 * 该方法在目标方法之前被调用。 若返回true：继续调用后续的拦截器和目标方法； 若返回false：不会再调用后续的拦截器和目标方法。
	 */
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		if (handler instanceof HandlerMethod) {
			IgnoreCheckoutToken ignoreCheckoutToken = ((HandlerMethod) handler).getMethodAnnotation(IgnoreCheckoutToken.class);
			// 如果请求的handler方法有IgnoreCheckoutToken注解，说明是不需要验证token的url，直接放行：
			if (null != ignoreCheckoutToken) {
				return true;
			} else {// 如果请求的handler方法没有IgnoreCheckoutToken注解，就说明是需要做token校验的：
				if(null != request.getCookies()){
					String token = CookieUtils.getCookieValue(request, COOKIE_TOKEN);
					if(StringUtils.isNotEmpty(token)){
						String jsonData = this.stringRedisTemplate.opsForValue().get(RedisKeyConstant.getToken(token));
						if (StringUtils.isNotEmpty(jsonData)) {
							//将redis中获取到的json数据转user对象：
							User user = MEPPER.readValue(jsonData, User.class);
							//更新redis中的token的生存时间
							this.stringRedisTemplate.expire(RedisKeyConstant.getToken(token), REDIS_SECONDS, TimeUnit.SECONDS);
							//更新redis中user值的生存时间：
							this.stringRedisTemplate.expire(RedisKeyConstant.getUserId(user.getId()), REDIS_SECONDS, TimeUnit.SECONDS);
							//更新cookie中token值的最大生存时间：
							CookieUtils.setCookie(request, response, COOKIE_TOKEN, token, TOKEN_FROM_COOKIE_SECONDS);
							// 把从Redis中获取的User对象放入request中，紧随拦截器之后执行的handler方法中可以直接获取该User：
							request.setAttribute(USER_FROM_REDIS, user);
							return true;
						}
					}
				}
			}
		}
		response.setStatus(response.SC_NO_CONTENT);
		return false;
	}
	
	/**
	 * 该方法在调用目标方法之后，但在渲染视图之前被调用。 可以对请求域中的属性或视图作出修改。
	 */
	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
			ModelAndView modelAndView) throws Exception {

	}

	/**
	 * 渲染视图之后被调用，释放资源。
	 */
	@Override
	public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
			throws Exception {

	}

}
