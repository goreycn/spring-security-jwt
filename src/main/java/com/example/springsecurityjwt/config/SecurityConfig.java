package com.example.springsecurityjwt.config;

import com.example.springsecurityjwt.service.JwtFilter;
import com.example.springsecurityjwt.util.JwtTokenUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;
import java.io.PrintWriter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**", "/css/**", "/image/**", "/*.html");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // V1 - V2
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // ???????????????
                .and()
                .authorizeRequests()
                .antMatchers("/product/**").hasRole("USER") // ?????? /product ????????????
                .antMatchers("/admin/**").hasRole("ADMIN") // ?????? /admin ????????????
                .anyRequest().authenticated() // ??????????????????, ??????????????????
                .and()
                .formLogin().loginPage("/myLogin.html")// ???????????????, ????????? configure(WebSecurity web) ????????????????????????
                .loginProcessingUrl("/login").successHandler((req, resp, authentication) -> {
                    final PrintWriter writer = resp.getWriter();
                    writer.println(JwtTokenUtil.createToken(authentication));
                    writer.flush();
                })
                .and()
                .csrf().disable().httpBasic()
                .and()
                .logout().logoutUrl("/logout").logoutSuccessHandler((req, resp, authentication) -> {
                    final PrintWriter writer = resp.getWriter();
                    writer.println("logout success");
                    writer.flush();
                })
                .and()
                .addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        final String pwd1 = encoder.encode("user");
        final String pwd2 = encoder.encode("admin");
        System.out.println(pwd1);
        System.out.println(pwd2);
    }
}
