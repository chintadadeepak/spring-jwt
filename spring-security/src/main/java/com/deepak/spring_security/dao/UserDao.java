package com.deepak.spring_security.dao;

import com.deepak.spring_security.models.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDao extends JpaRepository<Users, String> {
}
