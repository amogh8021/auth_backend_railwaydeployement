package com.example.learn.JwtAuth.Io;


import jakarta.validation.constraints.*;
import lombok.*;
import org.aspectj.bridge.IMessage;
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ProfileRequest {

  @NotBlank(message = "Name should not be empty")
  private String name;

  @Email(message = "Enter a valid email")
  @NotBlank(message = "Email should not be empty")
  private String email;

  @NotBlank(message = "Password should not be empty")
  @Size(min = 6, message = "Password must be at least 6 characters")
  private String password;
}
