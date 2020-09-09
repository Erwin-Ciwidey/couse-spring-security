package com.course.security.course.student;

import com.course.security.course.exceptions.ApiRequestException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
        new Student(1, "John Smith"),
        new Student(2, "John Doe"),
        new Student(3, "Jane Doe")
    );


    @GetMapping(path = "/{studentId}")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
        return STUDENTS.stream()
                       .filter(student -> studentId.equals(student.getStudentId()))
                       .findFirst()
                       .orElseThrow(() -> new ApiRequestException("Student" + studentId + "Not Found"));
    }
}
