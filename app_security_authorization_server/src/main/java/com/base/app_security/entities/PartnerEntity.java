package com.base.app_security.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "partners")
@Data
public class PartnerEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String clientId;
    
    private String clientName;
    
    private String clientSecret;
    
    private String scopes;
    
    private String grantTypes;
    
    private String authenticationMethods;
    
    private String redirectUri;
    
    private String redirectUriLogout;
}