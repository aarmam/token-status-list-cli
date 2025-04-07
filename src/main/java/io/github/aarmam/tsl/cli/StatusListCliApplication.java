package io.github.aarmam.tsl.cli;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.shell.command.annotation.CommandScan;

@CommandScan
@SpringBootApplication
public class StatusListCliApplication {

    public static void main(String[] args) {
        SpringApplication.run(StatusListCliApplication.class, args);
    }

}
