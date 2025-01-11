insert into customers (email, pwd) values
                                       ('admin@email.com', '$2a$10$OZzU7QT8QO78cGZlxrG56.Js0yCy82/CF93K.DTM1P5VBzODnI0cy'),
                                       ('jose@email.com', '$2a$10$OZzU7QT8QO78cGZlxrG56.Js0yCy82/CF93K.DTM1P5VBzODnI0cy'),
                                       ('pepe@email.com', '$2a$10$OZzU7QT8QO78cGZlxrG56.Js0yCy82/CF93K.DTM1P5VBzODnI0cy'),
                                       ('juan@email.com', '$2a$10$OZzU7QT8QO78cGZlxrG56.Js0yCy82/CF93K.DTM1P5VBzODnI0cy');

insert into roles(role_name, description, id_customer) values
                                                           ('ROLE_ADMIN', 'cant view account endpoint', 1),
                                                           ('ROLE_ADMIN', 'cant view cards endpoint', 2),
                                                           ('ROLE_USER', 'cant view loans endpoint', 3),
                                                           ('ROLE_USER', 'cant view balance endpoint', 4);
                                                           
insert into partners(
    client_id,
    client_name,
    client_secret,
    scopes,
    grant_types,
    authentication_methods,
    redirect_uri,
    redirect_uri_logout
)
values ('debuggeandoideas',
            'debuggeando ideas',
            '$2a$10$OZzU7QT8QO78cGZlxrG56.Js0yCy82/CF93K.DTM1P5VBzODnI0cy',
            'read,write',
            'authorization_code,refresh_token',
            'client_secret_basic,client_secret_jwt',
            'https://oauthdebugger.com/debug',
            'https://springone.io/authorized');