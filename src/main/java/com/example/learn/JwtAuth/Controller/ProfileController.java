package com.example.learn.JwtAuth.Controller;


import com.example.learn.JwtAuth.Io.ProfileRequest;
import com.example.learn.JwtAuth.Io.ProfileResponse;
import com.example.learn.JwtAuth.Service.EmailService;
import com.example.learn.JwtAuth.Service.ProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")

public class ProfileController {

    private final ProfileService profileService;
    private  final EmailService emailService;


    @PostMapping("/register")
    public ResponseEntity<ProfileResponse> register( @Valid @RequestBody ProfileRequest request){

        ProfileResponse response = profileService.createUser(request);

        emailService.sendWelcomeEmail(response.getEmail(), response.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);




    }


    @GetMapping("/profile")
  public ProfileResponse getProfile(@CurrentSecurityContext (expression = "authentication?.name") String email ){
  return profileService.getProfile(email);

  }

}
