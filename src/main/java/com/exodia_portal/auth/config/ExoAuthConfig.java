package com.exodia_portal.auth.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EntityScan({"com.exodia_portal.common", "com.exodia_portal.auth"})
@Configuration
@ComponentScan(basePackages = {"com.exodia_portal.common", "com.exodia_portal.auth"})
@EnableJpaRepositories({"com.exodia_portal.auth", "com.exodia_portal.common"})
public class ExoAuthConfig {
}
