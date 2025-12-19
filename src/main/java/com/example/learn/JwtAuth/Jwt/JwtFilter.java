package com.example.learn.JwtAuth.Jwt;


import com.example.learn.JwtAuth.Config.SecurityConfig;
import com.example.learn.JwtAuth.Service.AppUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;


@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final AppUserDetailsService appuserDetailsService;
    private final JwtUtil jwtUtil;

    private static final List<String> PUBLIC_URLS = List.of(
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/send-reset-otp",
            "/api/v1/auth/reset-password",
            "/api/v1/auth/logout"
    );


    @Override
    protected void doFilterInternal(HttpServletRequest request
            , HttpServletResponse response
            ,FilterChain filterChain) throws ServletException, IOException {

        String path = request.getServletPath();

        if (PUBLIC_URLS.contains(path)){
            filterChain.doFilter(request,response);
            return;

        }


        String jwt = null;
        String email = null;

        //1.check the authorization Header
        final String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader!=null && authorizationHeader.startsWith("Bearer")){
          jwt =   authorizationHeader.substring(7);
        }

        //2.if not found in the header, check the cookies
        if (jwt == null){
            Cookie[] cookies = request.getCookies();
            if (cookies!= null){
                for (Cookie cookie: cookies){
                    if ("jwt".equals(cookie.getName())){
                        jwt = cookie.getValue();
                        break;
                    }
                }
            }
        }

        //3.Validate the token and set the security context
         if (jwt!= null){
             email = jwtUtil.extractEmail(jwt);

             if (email!= null && SecurityContextHolder.getContext().getAuthentication() == null){
                 UserDetails userDetails = appuserDetailsService.loadUserByUsername(email);

                if (jwtUtil.validateToken(jwt,userDetails)){
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }

             }
         }


        filterChain.doFilter(request,response);

    }
}
