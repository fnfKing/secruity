package com.fnf.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
;
import java.io.IOException;

/**
 * @Author： 冯南飞
 * @Date： 2021/6/22 19:15
 **/
// 标记为配置类
@Configuration
// 启用web环境下权限控制的功能
@EnableWebSecurity
public class WebAppSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private MyUserDetailServiece userDetailServiece;

    // 登入识别设置
    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
//        builder
//                // 在内存中完成账号密码角色的设置
//                .inMemoryAuthentication()
//                .withUser("tom")
//                .password("123123")
//                .roles("ADMIN","学徒")
//                .and()
//                // 在内存中完成账号密码权限的设置
//                .withUser("fnf")
//                .password("123123")
//                .authorities("UPDATE","内门弟子")
//                ;
        builder
                .userDetailsService(userDetailServiece)
        ;
    }

    // 请求拦截
    @Override
    protected void configure(HttpSecurity security) throws Exception {

        JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
        repository.setDataSource(dataSource);

        security
                // 对请求进行授权
                .authorizeRequests()
                // 对index，jsp进行授权
                .antMatchers("/index.jsp")
                // 允许所有请求无条件访问
                .permitAll()
                // 对layui/**进行授权
                .antMatchers("/layui/**")
                // 允许所有请求无条件访问
                .permitAll()
                .antMatchers("/level1/**")  // 针对  level1/ 设置访问要求
                .hasRole("学徒")
                .antMatchers("/level2/**")// 具备内门弟子权限 才可以访问
                .hasAuthority("内门弟子")
                .and()
                // 对请求进行授权
                .authorizeRequests()
                // 任意请求
                .anyRequest()
                // 需要登录以后才可以访问
                .authenticated()
                .and()
                // 没有权限时，设置页面 ，不然会报403 错误 既没有权限
                .formLogin()
                // 指定登入页面的同时，会影响到提交登入表单地址，退出登入地址，登入失败地址
                // 进入该页面进行登入
                // /index.jsp GET - the login form                                                登入页面
                // /index.jsp POST - process the credentials and if valid authenticate the user   提交登入表单
                // /index.jsp?error GET - redirect here for failed authentication attempts        登入失败
                // /index.jsp?logout GET - redirect here after successfully logging out           退出登入
                // 设置授权信息时需要注意的是，范围小的放前面，范围大的放后面
                .loginPage("/index.jsp")
                // loginProcessingUrl()指定提交登入表单，会覆盖 loginPage()的默认值
                .loginProcessingUrl("/do/login.html")
                .usernameParameter("loginAcct")     // 定制的账号
                .passwordParameter("userPswd")      // 定制的密码
                .defaultSuccessUrl("/main.html")    // 登入成功后的页面
                .and()
//                .csrf()
//                .disable()                          // 禁用csrf功能
//                .and()
                .logout()                           // 开启注销功能
                .logoutUrl("/do/logout.html")       // 自定义注销功能的 URL 地址
                .logoutSuccessUrl("/index.jsp")     // 退出成功后前往的地址
                .and()
                .exceptionHandling()
//                .accessDeniedPage("/to/no/auth/page")   // 访问失败后来之
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                        httpServletRequest.setAttribute("message", "fnfnfnnf");
                        httpServletRequest.getRequestDispatcher("/WEB-INF/views/no_auth.jsp").forward(httpServletRequest, httpServletResponse);
                    }
                })
                .and()
                .rememberMe()    // 开启记住我功能
                .tokenRepository(repository)
        ;
    }
}
      