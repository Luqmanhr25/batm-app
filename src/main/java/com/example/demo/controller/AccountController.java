package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.demo.dto.Register;
import com.example.demo.dto.ChangePassword;
import com.example.demo.dto.ForgotPassword;
import com.example.demo.dto.Login;
import com.example.demo.model.Employee;
import com.example.demo.model.Role;
import com.example.demo.model.User;
import com.example.demo.repository.EmployeeRepository;
import com.example.demo.repository.RoleRepository;
import com.example.demo.repository.UserRepository;

@Controller
@RequestMapping("account")
public class AccountController {
    @Autowired
    private EmployeeRepository employeeRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @GetMapping
    public String index(){
        return "account/index";
    }

    @GetMapping("register")
    public String form(Model model) {
        model.addAttribute("register", new Register());
        return "account/register";
    }

    @PostMapping("register/save")
    public String save(Register register) {
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
                user.setPassword(register.getPassword());
                Role role = roleRepository.findById(4).orElse(null);
                user.setRole(role);
                userRepository.save(user);
                return "redirect:/account/login";
            }
        }
        return "redirect:/account/register";
    }

    @GetMapping("form-change-password")
    public String formChange(Model model) {
        model.addAttribute("changePassword", new ChangePassword());
        return "account/form-change-password";
    }

    
    @PostMapping("check")
    public String check(ChangePassword changePassword, Model model) {
        User user = userRepository.findByEmail(changePassword.getEmail());
        if (user == null) {
            return "account/register";
        } else if (changePassword.getNewPassword() == changePassword.getOldPassword()) {
            model.addAttribute("error", "Password Baru Anda tidak boleh sama");
            return "account/form-change-password";
        } else if (changePassword.getNewPassword().isEmpty() || changePassword.getNewPassword().equals(null)) {
            return "redirect:/account/form-change-password";
        } else if (!changePassword.getOldPassword().equals(user.getPassword())) {
            return "redirect:/account/form-change-password";
        } else {
            user.setPassword(changePassword.getNewPassword());
            userRepository.save(user);
        }
        return "redirect:/account/form-change-password";
    }


    @GetMapping("forgot-password")
    public String forgot(Model model) {
        model.addAttribute("forgotPassword", new ForgotPassword());
        return "account/forgot-password";
    }

    @PostMapping("forgot-password/check")
    public String checkEmail(ForgotPassword forgotPassword) {
        String emailExist = employeeRepository.findEmail(forgotPassword.getEmail());
        if (emailExist.equals(forgotPassword.getEmail())) {
            User user = userRepository.findUserByEmail(emailExist);
            user.setPassword(forgotPassword.getPassword());

            userRepository.save(user);
            return "account/login";
        }
        return "account/forgot-password";
    }

    @GetMapping("login")
    public String formLogin(Model model) {
        model.addAttribute("login", new Login());
        return "account/login";
    }

    @PostMapping("authenticating")
    public String login(Login login) {
        Employee responseLogin = employeeRepository.authenticate(login.getEmail());

        if (responseLogin.getEmail().equals(login.getEmail())) {
            return "redirect:/account";
        } else {
            return "redirect:/account/login/";
        }
    }
}
