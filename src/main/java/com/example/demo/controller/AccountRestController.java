package com.example.demo.controller;

import javax.servlet.http.HttpServletRequest;

import org.hibernate.dialect.MySQL55Dialect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.config.JwtTokenUtil;
import com.example.demo.config.MyUserDetails;
import com.example.demo.dto.ChangePassword;
import com.example.demo.dto.ForgotPassword;
import com.example.demo.dto.Login;
import com.example.demo.model.User;
import com.example.demo.repository.ParameterRepository;
import com.example.demo.repository.EmployeeRepository;
import com.example.demo.dto.Register;
import com.example.demo.dto.ResponseChangePassword;
import com.example.demo.handler.CustomResponse;
import com.example.demo.model.Employee;
import com.example.demo.model.JwtResponse;
import com.example.demo.model.Role;
import com.example.demo.repository.RoleRepository;
import com.example.demo.repository.UserRepository;

@RestController
@RequestMapping("api")
public class AccountRestController {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private EmployeeRepository employeeRepository;

    @Autowired
    private ParameterRepository parameterRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MyUserDetails myUserDetails;
    @Autowired 
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private HttpServletRequest request;

    @PostMapping("account/form-change-password")
    public ResponseEntity<Object> checkPassword(@RequestBody ChangePassword changePassword) {

        final String requestTokenHeader = request.getHeader("Authorization");        
		String username = null;
		String jwtToken = null;
        jwtToken = requestTokenHeader.substring(7);
        username = jwtTokenUtil.getUsernameFromToken(jwtToken);

        ResponseChangePassword responChangePassword = userRepository.findUser(username);

       String newPassword = passwordEncoder.encode(changePassword.getNewPassword()); 

       changePassword.setNewPassword(newPassword);



        System.out.println("respon cuy " +responChangePassword.getEmail());
        if (responChangePassword.getEmail().equals(null) && responChangePassword.getPassword().equals(null)) {
            return CustomResponse.generate(HttpStatus.OK, "user not found");
        } else if (changePassword.getNewPassword().equals(responChangePassword.getPassword())) {
            return CustomResponse.generate(HttpStatus.BAD_REQUEST,
                    "The new password cannot be the same as the old password");
        } else if (passwordEncoder.matches(changePassword.getOldPassword(),responChangePassword.getPassword())== false) {
            return CustomResponse.generate(HttpStatus.BAD_REQUEST, "password does not match");
        } else if (changePassword.getNewPassword().isEmpty() || changePassword.getNewPassword().equals(null)) {
            return CustomResponse.generate(HttpStatus.BAD_REQUEST,
                    "the field cannot be empty, check your input");
        } else {
            User user = userRepository.findByEmail(username);
            user.setPassword(changePassword.getNewPassword());
            userRepository.save(user);
            return CustomResponse.generate(HttpStatus.CREATED, "successfully changed your password");
        }
    }

    @PostMapping("account/register")
    public ResponseEntity<Object> save(@RequestBody Register register) {
        String emailExist = employeeRepository.findEmail(register.getEmail());
        if (emailExist == null) {
            Employee employee = new Employee();
            employee.setName(register.getName());
            employee.setEmail(register.getEmail());
            employeeRepository.save(employee);
            Boolean result = employeeRepository.findById(employee.getId()).isPresent();
            if (result) {
                User user = new User();
                user.setId(employee.getId());
                user.setPassword(passwordEncoder.encode(register.getPassword()));
                Role role = roleRepository.findById(5).orElse(null);
                user.setRole(role);
                userRepository.save(user);
                Boolean resultUser = userRepository.findById(employee.getId()).isPresent();
                if (resultUser) {
                    return CustomResponse.generate(HttpStatus.OK, "Register Successfully");
                }else{
                    employeeRepository.deleteById(employee.getId());
                    return CustomResponse.generate(HttpStatus.BAD_REQUEST, "Register Failed");
                }
            }
        }
        return CustomResponse.generate(HttpStatus.BAD_REQUEST, "Register Failed");
    }

    @PostMapping("account/authenticating")     
    public ResponseEntity<Object> login(@RequestBody Login login) {         
        try {             
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login.getEmail(), login.getPassword()));             
            SecurityContextHolder.getContext().setAuthentication(authentication);
            myUserDetails = (MyUserDetails) myUserDetails.loadUserByUsername(login.getEmail());
		    final String token = jwtTokenUtil.generateToken(myUserDetails);
            return CustomResponse.generate(HttpStatus.OK, "Login Successful", token);         
        } catch (Exception e) {             
            return CustomResponse.generate(HttpStatus.BAD_REQUEST, "Login Failed", null);         
        }     
    }

    @PostMapping("account/forgot-password")
    public ResponseEntity<Object> checkEmail(@RequestBody ForgotPassword forgotPassword) {
        User user = userRepository.findUserByEmail(forgotPassword.getEmail());
        if (user.getEmployee().getEmail().equals(forgotPassword.getEmail())) {
            user.setPassword(passwordEncoder.encode(forgotPassword.getPassword()));
            userRepository.save(user);
            return CustomResponse.generate(HttpStatus.OK, "Your Password has been Reset");
        }
        return CustomResponse.generate(HttpStatus.BAD_REQUEST, "Wrong Token");
    }
}