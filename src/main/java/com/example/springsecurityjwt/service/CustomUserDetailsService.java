package com.example.springsecurityjwt.service;

import cn.hutool.db.Db;
import cn.hutool.db.Entity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 数据库查询用户登录信息方式
 */
@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        List<Entity> userList = new ArrayList<>();
        try {
            userList = Db.use().findBy("user", "login", login);
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (userList.size() == 0) {
            throw new UsernameNotFoundException("User " + login + " was not found in db");
        }
        final Entity entity = userList.get(0);
        final String role = entity.getStr("role");

        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        GrantedAuthority authority = new SimpleGrantedAuthority(role);
        grantedAuthorities.add(authority);

        return new User(login, entity.getStr("password"), grantedAuthorities);
    }

}
