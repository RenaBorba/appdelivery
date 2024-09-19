package br.edu.ifpr.restapidelivery.repositorio;

import java.util.Optional;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import br.edu.ifpr.restapidelivery.model.Usuario;
import jakarta.transaction.Transactional;

public interface UsuarioRepositorio extends CrudRepository<Usuario, Long> { 

    Optional<Usuario> findByEmail(@Param("email") String email);
    
    @Modifying
    @Transactional
    @Query(value = "UPDATE usuario SET chave = :chave WHERE id = :id", nativeQuery = true)
    void updateChave(@Param("chave") String chave, @Param("id") long id);

    Optional<Usuario> findByChave(String chave);
    
}
