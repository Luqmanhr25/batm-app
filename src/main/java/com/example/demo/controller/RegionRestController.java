package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.handler.CustomResponse;
import com.example.demo.model.Region;
import com.example.demo.repository.ParameterRepository;
import com.example.demo.repository.RegionRepository;

@RestController
@RequestMapping("api")
public class RegionRestController {
    @Autowired
    private RegionRepository regionRepository;

    @Autowired
    private ParameterRepository parameterRepository;

    @GetMapping("regions")
    public ResponseEntity<Object> get() {
        return CustomResponse.generate(HttpStatus.OK, "Data Successfully Fetched", regionRepository.findAll());
    }

    @GetMapping("region/{id}")
    public ResponseEntity<Object> get(@PathVariable(required = true) Integer id) {
        return CustomResponse.generate(HttpStatus.OK, "id berhasil ditemukan", regionRepository.findById(id).orElse(null));
    }

    @PostMapping("region")
    public ResponseEntity<Object> save(@RequestBody Region region, @RequestHeader(name = "x-token") String token) {
        if(token.equals(parameterRepository.findById("x-token").get().getValue())) {
            Region result = regionRepository.save(region);
            if (regionRepository.findById(result.getId()).isPresent()) {
                return CustomResponse.generate(HttpStatus.OK, "Data Successfully Added");
            }
        }
        return CustomResponse.generate(HttpStatus.BAD_REQUEST, "Error Adding Data");
    }

    @PostMapping("region/{id}")
    public ResponseEntity<Object> delete(@PathVariable(required = true, name = "id") Integer id) {
        regionRepository.deleteById(id);
        return CustomResponse.generate(HttpStatus.OK, "id berhasil dihapus", !regionRepository.findById(id).isPresent());
    }
}
