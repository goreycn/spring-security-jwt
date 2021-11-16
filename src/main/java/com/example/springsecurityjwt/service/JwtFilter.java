package com.example.springsecurityjwt.service;

import cn.hutool.core.util.StrUtil;

import com.example.springsecurityjwt.util.JwtTokenUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;


public class JwtFilter extends GenericFilterBean {
    private final static String HEADER_AUTH_NAME = "Authorization";

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        final String authToken = req.getHeader(HEADER_AUTH_NAME);
        if (StringUtils.hasText(authToken)) {
            final String[] s = authToken.split(" ");
            if ("Bearer".equals(s[0]) && StrUtil.isNotEmpty(s[1])) {
                final Authentication authentication = JwtTokenUtil.parseAuthentication(s[1]);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
