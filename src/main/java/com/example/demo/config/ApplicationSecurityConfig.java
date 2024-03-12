package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class ApplicationSecurityConfig {

@Autowired
	private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

@Autowired
	private JwtRequestFilter jwtRequestFilter;

    @Bean // termasuk dependecies injection menjalankan
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // white listing = adalah akses yang boleh masuk
    // black listing = adalah akses yang tidak boleh masuk atau inputan
    // .authenticated = sembarang akses atau yang login saja bisa akses
    // permit all = bisa akses tanpa login
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        try {

            http
                    .csrf().disable()
                    .authorizeRequests((requests) -> requests
                            .antMatchers("/account/authenticating", "/account/register").authenticated()
                            .antMatchers("api/regions").hasAuthority("Officer")
                            // .anyRequest().permitAll()
                    )
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)
                    .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint);

            return http.build();
        } catch (Exception e) {
            e.printStackTrace();
            return null; 
        }
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}