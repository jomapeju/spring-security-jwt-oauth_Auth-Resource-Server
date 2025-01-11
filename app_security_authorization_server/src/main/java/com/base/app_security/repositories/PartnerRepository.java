package com.base.app_security.repositories;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.base.app_security.entities.PartnerEntity;

public interface PartnerRepository extends CrudRepository<PartnerEntity, Long> {

    Optional<PartnerEntity>findByClientId(String clientId);
}
