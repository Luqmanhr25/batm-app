package com.example.demo.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    private JwtTokenFilter jwtTokenFilter;

    @Bean // termasuk dependecies injection menjalankan
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // white listing = adalah akses yang boleh masuk
    // black listing = adalah akses yang tidak boleh masuk atau inputan
    // .anyrequest = jenis reques apapun
    // authenticate = boleh di lihat atau di akses hanya dengan login tanpa liat
    // role
    // permit all = bisa akses tanpa login
    // @Bean
    // public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // http
    // .csrf().disable()
    // .authorizeHttpRequests((auth) -> {
    // try {
    // auth
    // .antMatchers("/account/authenticating", "/account/register")
    // .authenticated()
    // .antMatchers("api/regions").hasAuthority("manager")
    // .anyRequest()
    // .permitAll()
    // .and()
    // .exceptionHandling()
    // .authenticationEntryPoint(jwtAuthenticationEntryPoint)
    // .and()
    // .sessionManagement()
    // .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    // http.addFilterBefore(jwtRequestFilter,
    // UsernamePasswordAuthenticationFilter.class);
    // } catch (Exception e) {
    // throw new RuntimeException(e);
    // }
    // });
    // return http.build();
    // }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        try {
            http
                    .csrf().disable()
                    .authorizeRequests((requests) -> requests
                            .antMatchers("/account/authenticating", "/account/register", "/account/forgot-password")
                            .authenticated()
                            // .antMatchers("/api/account/forgot-password").permitAll()
                            .antMatchers("/api/regions").hasAuthority("Staff")
                            .anyRequest().permitAll()
                    )
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
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
