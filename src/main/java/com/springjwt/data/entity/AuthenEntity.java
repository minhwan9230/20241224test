package com.springjwt.data.entity;

import jakarta.persistence.*;
import lombok.*;

@Data
@Table(name="authentbl")
@Builder
@Entity
@AllArgsConstructor
@NoArgsConstructor
public class AuthenEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(nullable = false)
    private String username;
    @Column(nullable = false)
    private String password;
    private String role;
}
