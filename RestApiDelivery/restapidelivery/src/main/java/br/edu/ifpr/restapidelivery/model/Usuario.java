package br.edu.ifpr.restapidelivery.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Entity
public class Usuario {
  
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @NotNull
    private String nome;
    @NotNull
    private String email;
    @NotNull
    @Size(min = 8, message= "Senha deve conter no mínimo de 8 caracteres")
    private String senha;
    @NotNull
    private String chave;
    

        public Usuario() {
    }

        public Usuario( String nome, String email, String senha) {
        this.nome = nome;
        this.email = email;
        this.senha = senha;

    }


    public Long getId() {
        return this.id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNome() {
        return this.nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getEmail() {
        return this.email;
    }

    public void setLogin(String email) {
        this.email = email;
    }

    public String getSenha() {
        return this.senha;
    }

    public void setSenha(String senha) {
        this.senha = senha;
    }

    @Override
    public String toString() {
        return "{" +
            "id='" + getId() + "'"+
            "nome='" + getNome() + "'" +
            "login='" + getEmail() + "'"+
            "senha='" + getSenha() + "'"+
            "}";
    }

    public String getChave() {
        return chave;
    }

    public void setChave(String chave) {
        this.chave = chave;
    }

}
