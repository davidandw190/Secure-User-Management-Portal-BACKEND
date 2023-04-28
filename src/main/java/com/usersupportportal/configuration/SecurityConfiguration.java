package com.usersupportportal.configuration;


import com.usersupportportal.filter.JwtAccessDeniedHandler;
import com.usersupportportal.filter.JwtAuthenticationEntryPoint;
import com.usersupportportal.filter.JwtAuthorizationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration {
    private JwtAuthorizationFilter jwtAuthorizationFilter;
    private JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private UserDetailsService userDetailsService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public SecurityConfiguration(JwtAuthorizationFilter jwtAuthorizationFilter,
                                 JwtAccessDeniedHandler jwtAccessDeniedHandler,
                                 JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                                 UserDetailsService userDetailsService,
                                 BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.jwtAuthorizationFilter = jwtAuthorizationFilter;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        http
                .csrf().disable().cors()
                .and()
                .authorizeHttpRequests().anyRequest().authenticated()
                .and()
                .exceptionHandling().accessDeniedHandler(jwtAccessDeniedHandler)
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                .sessionManagement().sessionCreationPolicy(STATELESS)
                .and()
                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private RequestMatcher getExcludedURLS() {
        return new OrRequestMatcher(
                new AntPathRequestMatcher("/api/toBeCreated/**"),
                new AntPathRequestMatcher("/api/toBeCreated/**"),
                new AntPathRequestMatcher("/api/toBeCreated/**")
        );
    }

    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
//        http.csrf().disable().cors().and()
//                .sessionManagement().sessionCreationPolicy(STATELESS)
//                .and().authorizeRequests().anyRequest().authenticated()
//                .and()
//                .exceptionHandling().accessDeniedHandler(jwtAccessDeniedHandler)
//                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
//                .and()
//                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);
//        return http.build();
//    }






}

