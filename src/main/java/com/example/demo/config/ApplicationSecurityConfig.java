package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
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
    private MyUserDetails myUserDetails;

    @Autowired  
    private JwtAuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private JwtTokenFilter jwtTokenFilter;

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(myUserDetails);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // authorization
    // @Bean
    // public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    //     http
    //         .csrf().disable()
    //         .authorizeHttpRequests()
    //         .antMatchers("/api/account/authenticating", "/api/account/register")
    //         .permitAll()
    //         .antMatchers("api/regions").hasAuthority("Staff")
    //         .anyRequest()
    //         .authenticated()
    //         .and()
    //         .exceptionHandling()
    //         .authenticationEntryPoint(authenticationEntryPoint)
    //         .and()
    //         // .authenticationProvider(authenticationProvider())
    //         .sessionManagement()
    //         .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    //         http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
            
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
                    .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
                    
            return http.build();
        } catch (Exception e) {
            e.printStackTrace();
            return null; 
        }
    }
}
