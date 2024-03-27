create table -- таблица пользователей
    if not exists users5 (
        id serial,
        login text,
        password text,
        email text,
        countryCode text,
        isPublic text,
        phone text,
        image text
    );

create table -- таблица действительных на текущий момент токенов
    if not exists tokens (
        token text,
        login text
    );

create table -- таблица связей друзей (не половых)
    if not exists friends3 (
        login1 text, 
        login2 text, 
        createdAt timestamptz
    );

create table 
    if not exists posts3 (
        id text, 
        login text, 
        content text, 
        tags text[], 
        createdAt text, 
        likes int, 
        dislikes int, 
        videoLink text
    );
create table -- таблица лайков/дизлайков, 0 - дизлайк, 1 - лайк
    if not exists reactions (
        login text, 
        postId text, 
        reaction boolean
    );