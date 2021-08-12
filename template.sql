CREATE TABLE users (
 id CHAR(10) NOT NULL PRIMARY KEY,
 status VARCHAR(1024) NOT NULL,
 display_name VARCHAR(256) NOT NULL,
 display_id VARCHAR(20) NOT NULL,
 icon_uri VARCHAR(1024)
);


CREATE TABLE tmp_users (
 id CHAR(64) NOT NULL PRIMARY KEY,
 expired_at TIMESTAMP(10) NOT NULL
);


CREATE TABLE posts (
 id INT NOT NULL PRIMARY KEY,
 user_id CHAR(10) NOT NULL,
 posted_at TIMESTAMP(10) NOT NULL,
 content VARCHAR(5096) NOT NULL,

 FOREIGN KEY (user_id) REFERENCES users (id)
);


CREATE TABLE settings (
 id CHAR(10) NOT NULL PRIMARY KEY,
 two_factor BIT(10) NOT NULL,

 FOREIGN KEY (id) REFERENCES users (id)
);


CREATE TABLE credentials (
 id CHAR(10) NOT NULL PRIMARY KEY,
 user_id CHAR(10),
 tmp_user_id CHAR(64),
 type CHAR(20) NOT NULL,
 uid VARCHAR(128) NOT NULL,
 display_name VARCHAR(128),
 token VARCHAR(512),
 salt CHAR(20),
 icon_uri VARCHAR(1024),

 FOREIGN KEY (user_id) REFERENCES users (id),
 FOREIGN KEY (tmp_user_id) REFERENCES tmp_users (id)
);


CREATE TABLE hearts (
 id CHAR(10) NOT NULL PRIMARY KEY,
 post_id INT NOT NULL,
 user_id CHAR(10) NOT NULL,
 created_at TIMESTAMP(10),

 FOREIGN KEY (post_id) REFERENCES posts (id),
 FOREIGN KEY (user_id) REFERENCES users (id)
);


CREATE TABLE sessions (
 id CHAR(10) NOT NULL PRIMARY KEY,
 token CHAR(64),
 expired_at TIMESTAMP(10),
 established_at TIMESTAMP(10),
 last_used_at TIMESTAMP(10),
 ip CHAR(20),
 useragent VARCHAR(128),
 user_id CHAR(10),

 FOREIGN KEY (user_id) REFERENCES users (id)
);
