CREATE TABLE `user` (
                        `id` int(28) NOT NULL,
                        `login` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
                        `password` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
                        `role` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
                        PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
INSERT INTO `demo`.`user`(`id`, `login`, `password`, `role`) VALUES (1, 'user', 'user', 'ROLE_USER');
INSERT INTO `demo`.`user`(`id`, `login`, `password`, `role`) VALUES (2, 'admin', 'admin', 'ROLE_ADMIN');