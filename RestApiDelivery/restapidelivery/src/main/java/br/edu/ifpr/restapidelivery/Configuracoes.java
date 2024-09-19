package br.edu.ifpr.restapidelivery;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class Configuracoes {

     @Autowired
     
     private FiltroToken filtroToken;

     @Bean
     public SecurityFilterChain securityfilterChain(HttpSecurity http) throws Exception {
        return http.csrf((csrf) -> csrf.disable()).
        sessionManagement((session) -> session.
        sessionCreationPolicy(SessionCreationPolicy.STATELESS)).
        authorizeHttpRequests((authorize) -> authorize.
        requestMatchers(HttpMethod.POST, "/usuario/login","/usuario/criar").
        permitAll().anyRequest().authenticated()).
        addFilterBefore(filtroToken, UsernamePasswordAuthenticationFilter.class)
        .build();
     }

}