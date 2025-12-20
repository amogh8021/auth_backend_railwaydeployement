package com.example.learn.JwtAuth.entity;



import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.sql.Timestamp;


@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data




public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;


    @Column(unique = true)
    private String userId;

    private String name;

    @Column(unique = true)
    private String email;
    private String password;
    private String verifyOtp;
    private Boolean isAccountVerified;
    private Long verifyOtpExpired;
    private String resetOtp;
    private Long resetOtpExpireAt;

    @CreationTimestamp
    @Column(updatable = false)
    private Timestamp createdAt;

    @UpdateTimestamp
    private Timestamp updatedAt;
}
