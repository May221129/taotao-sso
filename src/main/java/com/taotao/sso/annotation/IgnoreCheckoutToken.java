package com.taotao.sso.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 自定义注解。
 * 作用：用于Controller中不需要验证token的Handler方法，加了该注解，表示忽略验证token。
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface IgnoreCheckoutToken {
	
}
