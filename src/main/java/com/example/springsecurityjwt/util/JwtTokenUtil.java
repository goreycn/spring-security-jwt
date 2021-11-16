package com.example.springsecurityjwt.util;

import cn.hutool.core.util.ArrayUtil;
import cn.hutool.db.Db;
import cn.hutool.db.Entity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.SneakyThrows;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class JwtTokenUtil {
    private static long tokenExpiration = 24 * 60 * 60 * 1000;
    private static String tokenSignKey = "123456";
    private static String userRoleKey = "userRole";

    public static String createToken(Authentication auth) {
        String userName;
        final Object p = auth.getPrincipal();
        if (p instanceof UserDetails) {
            userName = ((UserDetails) p).getUsername();
        } else {
            userName = p.toString();
        }

        List roleList = new ArrayList();
        for (GrantedAuthority authority : auth.getAuthorities()) {
            roleList.add(authority.getAuthority());
        }
        String role = ArrayUtil.join(roleList.toArray(), ",");

        return Jwts.builder().setSubject(userName).claim(userRoleKey, role)
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpiration))
                .signWith(SignatureAlgorithm.HS512, tokenSignKey).compressWith(CompressionCodecs.GZIP).compact();

    }

    public static String createToken(String userName) {
        return Jwts.builder().setSubject(userName)
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpiration))
                .signWith(SignatureAlgorithm.HS512, tokenSignKey).compressWith(CompressionCodecs.GZIP).compact();
    }

    public static String createToken(String userName, String role) {
        return Jwts.builder().setSubject(userName).claim(userRoleKey, role)
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpiration))
                .signWith(SignatureAlgorithm.HS512, tokenSignKey).compressWith(CompressionCodecs.GZIP).compact();
    }

    public static String getUserNameFromToken(String token) {
        return Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody().getSubject();
    }

    public static String getUserRoleFromToken(String token) {
        final Claims claims = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody();
        return claims.get(userRoleKey).toString();
    }

    @SneakyThrows
    public static Authentication parseAuthentication(String token) {
        final Claims claims = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody();
        final String username = claims.getSubject();

        final Entity entity = Db.use().get("user", "login", username);
        UserBean user = new UserBean();
        user.setId(entity.getLong("id"));
        user.setLogin(entity.getStr("login"));
        user.setPassword(entity.getStr("password"));
        user.setRole(entity.getStr("role"));

        return new UsernamePasswordAuthenticationToken(user, token, user.getAuthorities());
    }
}
