package com.example.learn.JwtAuth.Service;


import com.example.learn.JwtAuth.Entity.User;
import com.example.learn.JwtAuth.Io.ProfileRequest;
import com.example.learn.JwtAuth.Io.ProfileResponse;
import com.example.learn.JwtAuth.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Date;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
@Slf4j
public class ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    public ProfileResponse createUser(ProfileRequest request){

        if (userRepository.existsByEmail(request.getEmail())) {

            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");




        }


        User newUser = User.builder()
                .userId(UUID.randomUUID().toString())
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .verifyOtp(null)
                .resetOtp(null)
                .resetOtpExpireAt(0L)
                .isAccountVerified(false)
                .build();
        User savedUser = userRepository.save(newUser);
        return ConvertToProfileResponse(savedUser);





    }

    private ProfileResponse ConvertToProfileResponse(User savedUser) {
        return ProfileResponse.builder()
                .userId(savedUser.getUserId())
                .name(savedUser.getName())
                .email(savedUser.getEmail())
                .isAccountVerified(savedUser.getIsAccountVerified())
                .build();
    }

    public ProfileResponse getProfile(String email){
        User existingUser = userRepository.findByEmail(email)
                .orElseThrow(()->new UsernameNotFoundException("user not found" + email));
        return ConvertToProfileResponse(existingUser);
    }

    public void sendResetOtp(String email){
        User existingUser = userRepository.findByEmail(email)
                .orElseThrow(()->new UsernameNotFoundException("user not found" + email));

        //Generate 6 digit otp
       String otp =  String.valueOf(ThreadLocalRandom.current().nextInt(100000,1000000));

       //calculate expiry time (current time + 10 min in milliSecond)

        long otpExpiration = System.currentTimeMillis()+(10*60*1000);

        //update the profile ENtity

        existingUser.setResetOtp(otp);
        existingUser.setResetOtpExpireAt(otpExpiration);

        //save into the database

        userRepository.save(existingUser);

        try{
            emailService.sendResetPasswordOtp(existingUser.getEmail(), otp);

        }

        catch (Exception e){
            throw new RuntimeException("unable to send the otp ");
        }
    }

    public void ResetPassword(String email , String otp, String newPassword){

        log.info("Received password reset request for email: {}", email);

      User existingUser =   userRepository.findByEmail(email)
                .orElseThrow(()-> new UsernameNotFoundException("user not found " + email));

        log.info("Expected OTP: {}", existingUser.getResetOtp());
        log.info("Received OTP: {}", otp);
        log.info("OTP Expiry: {}", existingUser.getResetOtpExpireAt());
        log.info("Current Time: {}", System.currentTimeMillis());

        if (existingUser.getResetOtp() == null || !existingUser.getResetOtp().equals(otp)){
            throw new RuntimeException("Invalid OTP");
        }

        if (existingUser.getResetOtpExpireAt()<System.currentTimeMillis()){
            throw new RuntimeException("OTP is expired");
        }

        existingUser.setPassword(passwordEncoder.encode(newPassword));
        existingUser.setResetOtp(null);
        existingUser.setResetOtpExpireAt(0L);

        userRepository.save(existingUser);

        log.info("Password reset successful for user: {}", email);


    }

    public void sendOtp(String email){

      User existingUser =   userRepository.findByEmail(email)
                .orElseThrow(()-> new UsernameNotFoundException("user not found " +email));

      if (existingUser.getIsAccountVerified() != null && existingUser.getIsAccountVerified()){
          return;

      }

      //Generate 6 digit otp

        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000 , 1000000));


        //calculate expiry time (current time + 24hr in milliSecond)

        long otpExpiration = System.currentTimeMillis()+(24*60*60*1000);
        existingUser.setVerifyOtp(otp);
        existingUser.setVerifyOtpExpired(otpExpiration);

        //save in to the database
        userRepository.save(existingUser);

        try{
            emailService.sendVerifyAccountOtp(existingUser.getEmail(), otp);
        }

        catch (Exception e ){
            throw  new RuntimeException("unable to send the otp ");
        }


    }





    public void verifyOtp(String email, String otp){

        User existingUser = userRepository.findByEmail(email)
                .orElseThrow(()->new UsernameNotFoundException("user not found" + email));
        log.info("expected otp: {}", existingUser.getVerifyOtp());
        log.info("Received OTP: {}", otp);
        log.info("OTP Expiry: {}", existingUser.getResetOtpExpireAt());
        log.info("Current Time: {}", System.currentTimeMillis());


        if (existingUser.getVerifyOtp() == null || !existingUser.getVerifyOtp().equals(otp) ){
            throw new RuntimeException("invalid otp");
        }

        if (existingUser.getVerifyOtpExpired()<System.currentTimeMillis()){
            throw new RuntimeException("otp is expired ");
        }



        existingUser.setIsAccountVerified(true);
        existingUser.setVerifyOtpExpired(0L);
        existingUser.setVerifyOtp(null);
        userRepository.save(existingUser);

        log.info("Password reset successful for user: {}", email);

    }






    String getLoggedInUserId(String email){
   User user =  userRepository.findByEmail(email)
          .orElseThrow(()->new UsernameNotFoundException("user not found" + email));
   return user.getUserId();
    }

}