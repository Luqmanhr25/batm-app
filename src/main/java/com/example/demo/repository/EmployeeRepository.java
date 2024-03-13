package com.example.demo.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.example.demo.model.Employee;

@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Integer>{
    Optional<Employee> findByEmail(String email);

    @Query(value = "SELECT email FROM tb_m_employee WHERE email = ?1", nativeQuery = true)
    public String findEmail(String email);
    
    // @Query(
    //     """
    //     SELECT new com.example.demo.dto.ResponseLogin(e.name, e.email) FROM Employee e WHERE e.email = ?1
    // """)
    // public ResponseLogin authenticate(String email);

    @Query("""
            SELECT e FROM Employee e WHERE e.email = ?1
            """)
    public Employee authenticate(String email);
} 
