package br.edu.ifpr.restapidelivery;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
public class RestapideliveryApplication {

	public static void main(String[] args) {
		SpringApplication.run(RestapideliveryApplication.class, args);
	}

}
