-- Your SQL goes here
CREATE TABLE `account` (
    id CHAR(32) NOT NULL COMMENT 'id',
    phone CHAR(11) NOT NULL UNIQUE COMMENT '手机',
    `password` VARCHAR(192) NOT NULL COMMENT '密码',
    salt VARCHAR(192) NOT NULL COMMENT '哈希盐值',
    login_error_count INT NOT NULL DEFAULT 0 COMMENT '密码错误次数',
    last_login_at BIGINT COMMENT '最后登录时间',
    last_error_at BIGINT COMMENT '最后密码错误',
    create_at BIGINT NOT NULL COMMENT '创建时间',
    update_at BIGINT COMMENT '更新时间',
    PRIMARY KEY (id)
);