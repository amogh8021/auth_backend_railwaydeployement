package com.example.learn.JwtAuth.Service;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender javaMailSender;


    @Value("${spring.mail.properties.mail.smtp.from}")
     private  String fromEmail;

     public void sendWelcomeEmail(String toEmail, String name){
         SimpleMailMessage message = new SimpleMailMessage();
         message.setFrom(fromEmail);
         message.setTo(toEmail);
         message.setSubject("welcome to our platform  ");
         message.setText("Hello" +name+ ",\n\n Thanks for registering with us \n\n Regards, \nTeam Amogh");
         javaMailSender.send(message);
     }

     public void sendResetPasswordOtp(String toUser, String otp){
         SimpleMailMessage message = new SimpleMailMessage();
         message.setFrom(fromEmail);
         message.setTo(toUser);
         message.setSubject("otp for password-reset");
         message.setText("your 6 digit otp for the password reset is :" + otp +"\n use this otp to reset the password");
         javaMailSender.send(message);
     }

    public void sendVerifyAccountOtp(String toUser, String otp){
         SimpleMailMessage message = new SimpleMailMessage();
         message.setTo(toUser);
         message.setText("otp for verifying your account is " + otp );
         message.setSubject("otp for account verification");
         message.setFrom(fromEmail);
         javaMailSender.send(message);

    }
}
