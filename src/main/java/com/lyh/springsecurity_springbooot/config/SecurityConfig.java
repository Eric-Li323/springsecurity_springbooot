package com.lyh.springsecurity_springbooot.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//AOP  （作用等同与拦截器，但是更简化）
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //授权    链式编程
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人都可以访问，功能页只有对应有权限的人才能够使用
        //请求授权的页面

        //1.认证请求
        //请求授权的规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限会默认到登录页面,需要开启登录页面
        //  /login
        http.formLogin().loginPage("/toLogin").usernameParameter("user").passwordParameter("pwd").loginProcessingUrl("/login");

        //防止网站攻击   get默认不安全  post
        http.csrf().disable();  //关闭csrf功能，登出失败可能的原因

        //注销，开启注销功能，跳到首页
        http.logout().logoutSuccessUrl("/");

        //开启记住我功能  cookie:默认保存两周   自定义接受前端参数
        http.rememberMe().rememberMeParameter("remember");

    }

    //认证      springboot2.1.x 可以直接使用
    //密码编码   passwordEncoder
    //在spring security 5.0+  新增了很多的加密算法
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //这些数据正常应该从数据库中取
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("kuangshen").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3");
    }

}
