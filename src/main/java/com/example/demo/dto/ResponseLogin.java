package com.example.demo.dto;

public class ResponseLogin {
    private String name;
    private String email;
    private String password;
    private String role;
    

    public ResponseLogin(String name, String email) {
        this.name = name;
        this.email = email;
    }

    public ResponseLogin() {
    }

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    public String getRole() {
        return role;
    }
    public void setRole(String role) {
        this.role = role;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    
}
