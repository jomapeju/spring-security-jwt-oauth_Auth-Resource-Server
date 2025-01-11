package com.base.app_security.repositories;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.base.app_security.entities.CustomerEntity;

public interface CustomerRepository extends CrudRepository<CustomerEntity, Long> {

    Optional<CustomerEntity> findByEmail(String email);
}
