package com.hodolog.api.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Base64;

@Data
@ConfigurationProperties(prefix = "hodolman")
public class AppConfig {

    public String jwtKey;
}
