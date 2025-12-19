package com.example.learn.JwtAuth.Controller;


import com.example.learn.JwtAuth.Config.SecurityConfig;
import com.example.learn.JwtAuth.Entity.User;
import com.example.learn.JwtAuth.Io.AuthRequest;
import com.example.learn.JwtAuth.Io.AuthResponse;
import com.example.learn.JwtAuth.Io.ResetPasswordRequest;
import com.example.learn.JwtAuth.Jwt.JwtUtil;
import com.example.learn.JwtAuth.Repository.UserRepository;
import com.example.learn.JwtAuth.Service.AppUserDetailsService;
import com.example.learn.JwtAuth.Service.ProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.Response;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.parameters.P;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j



public class AuthController {

   private final AuthenticationManager authenticationManager;
   private final AppUserDetailsService appUserDetailsService;
   private final UserRepository userRepository;
   private final JwtUtil jwtUtil;
   private final ProfileService profileService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        Map<String, Object> error = new HashMap<>();

        try {
            authenticate(request.getEmail(), request.getPassword());
           final UserDetails userDetails =  appUserDetailsService.loadUserByUsername(request.getEmail());

         final String jwtToken =   jwtUtil.generateToken(userDetails);
            ResponseCookie cookie = ResponseCookie.from("jwt" , jwtToken)
                    .httpOnly(true)
                    .path("/")
                    .maxAge(Duration.ofDays(1))
                    .sameSite("Strict")
                    .build();

            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE,cookie.toString())
                    .body(new AuthResponse(request.getEmail(), jwtToken,"Login Successful "));


        } catch (BadCredentialsException e) {
            error.put("error", true);
            error.put("message", "Email or password is incorrect");
        } catch (DisabledException e) {
            error.put("error", true);
            error.put("message", "Account is disabled");
        } catch (Exception e) {
            error.put("error", true);
            error.put("message", "Authentication failed");
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }



    private void authenticate (String email , String password ){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email,password));
    }

    @GetMapping("is-authenticated")
    public ResponseEntity<Boolean> isAuthenticated(@CurrentSecurityContext (expression = "authentication?. name")String email)
    {
        return ResponseEntity.ok(email!=null);
    }

  @PostMapping("/send-reset-otp")
    public void SendResetOtp(@RequestParam String email){
        try{
            profileService.sendResetOtp(email);

        }
        catch (Exception e){
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,e.getMessage());

        }
  }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try {
            profileService.ResetPassword(request.getEmail(), request.getOtp(), request.getNewPassword());
            return ResponseEntity.ok("Password reset successful");
        } catch (UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        } catch (RuntimeException e) {
            // OTP invalid, expired, etc.
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Something went wrong");
        }
    }



@PostMapping("send-otp")
    public void sendVerifyOtp(@CurrentSecurityContext (expression = "authentication?.name")String email){
        try
        {
            profileService.sendOtp(email);
        }
        catch (Exception e){
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR , e.getMessage());
        }
}


@PostMapping("/verify-otp")
public void verifyEmail(@RequestBody Map<String, Object> request ,
                        @CurrentSecurityContext(expression = "authentication?.name") String email){


        if (request.get("otp").toString()== null){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing details");
        }
        try{
            profileService.verifyOtp(email,request.get("otp").toString());
        }

        catch (Exception e){
            throw  new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }

}

    @GetMapping("/is-verified")
    public ResponseEntity<Boolean> isUserVerified(
            @CurrentSecurityContext(expression = "authentication?.name") String email
    ) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        boolean isVerified = user.getIsAccountVerified();


        log.info("Checking verification status for user: {}, Verified: {}", email, isVerified);

        return ResponseEntity.ok(isVerified);
    }



}
