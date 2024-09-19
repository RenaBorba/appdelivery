package br.edu.ifpr.restapidelivery;

import java.io.IOException;

import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties.Security;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import br.edu.ifpr.restapidelivery.model.Usuario;
import br.edu.ifpr.restapidelivery.repositorio.UsuarioRepositorio;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FiltroToken extends OncePerRequestFilter {

    @Autowired
    private UsuarioRepositorio _usuarioRepositorio;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
    
           
                var authenticationHeader = request.getHeader("Authorization");

                if (authenticationHeader != null) {
                    Optional<Usuario> usuario = this._usuarioRepositorio.findByChave(authenticationHeader);

                    if (usuario.isPresent()) {
                        var authentication = new UsernamePasswordAuthenticationToken(usuario.get(), null, null);

                        SecurityContextHolder.getContext().setAuthentication(authentication);

                    } else {
                        response.setStatus(HttpStatus.FORBIDDEN.value());
                    }

                } else {
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                }

                filterChain.doFilter(request, response);
    }
    
}
