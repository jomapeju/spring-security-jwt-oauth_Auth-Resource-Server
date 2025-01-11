CREATE TABLE customers (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(50) NOT NULL,
    pwd VARCHAR(500) NOT NULL
);

CREATE TABLE roles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50),
    description VARCHAR(100),
    id_customer BIGINT,
    CONSTRAINT fk_customer FOREIGN KEY (id_customer) REFERENCES customers(id)
);

create table partners (
	  id BIGINT AUTO_INCREMENT PRIMARY KEY,
	  client_id VARCHAR(256),
	  client_name VARCHAR(256),
	  client_secret VARCHAR(256),
	  scopes VARCHAR(256),
	  grant_types VARCHAR(256),
	  authentication_methods VARCHAR(256),
	  redirect_uri VARCHAR(256),
	  redirect_uri_logout VARCHAR(256)
);
