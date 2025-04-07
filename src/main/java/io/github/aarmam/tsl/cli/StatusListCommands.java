package io.github.aarmam.tsl.cli;

import com.authlete.cose.COSEException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import io.github.aarmam.tsl.StatusList;
import io.github.aarmam.tsl.StatusListToken;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.shell.command.annotation.Command;
import org.springframework.shell.command.annotation.Option;
import org.springframework.shell.standard.ShellOption;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

@Command
@RequiredArgsConstructor
public class StatusListCommands {
    private final Key signingKey;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${status-list.path}")
    private String path;
    @Value("${status-list.uri}")
    private URI uri;
    @Value("${status-list.expires}")
    private Duration expires;
    @Value("${status-list.time-to-live}")
    private Duration ttl;
    @Value("${spring.ssl.bundle.pem.status-list-issuer.key.alias}")
    private String keyId;

    private StatusList statusList;

    @Command(command = "generate", description = "Generates the status list in specified format")
    public String generate(@Option(defaultValue = "1") Integer bits, @Option(defaultValue = "1048576") Integer size,
                           @Option(defaultValue = "JSON", description = "Status list encoding JSON or CBOR") String statusListEncoding) throws IOException {
        statusList = new StatusList(size, bits);
        saveStatusList(statusList, statusListEncoding);
        return "Status list token generated";
    }

    @Command(command = "load", alias = "l", description = "Loads the status list in JSON or CBOR Hex format")
    public String load(@Option(defaultValue = "JSON", description = "Status list encoding JSON or CBOR") String statusListEncoding) throws IOException {
        statusList = getStatusList(statusListEncoding);
        return "Status list loaded";
    }

    @Command(command = "save", description = "Saves the status list in JSON or CBOR Hex format")
    public String save(@Option(defaultValue = "JSON", description = "Status list encoding JSON or CBOR") String statusListEncoding) throws IOException {
        saveStatusList(statusList, statusListEncoding);
        return "Status list saved";
    }

    @Command(command = "get", alias = "g", description = "Gets the status at index")
    public String get(@ShellOption @NonNull Integer index) {
        return "Status at index %d is %d".formatted(index, Objects.requireNonNull(statusList, "Status list not loaded").get(index));
    }

    @Command(command = "set", alias = "s", description = "Sets the status at index")
    public String set(@ShellOption @NonNull Integer index, @ShellOption @NonNull Integer status) {
        Objects.requireNonNull(statusList, "Status list not loaded").set(index, status);
        return "Status %d set at index %d".formatted(status, index);
    }

    @Command(command = "sign", description = "Generates and signs the status list token")
    public String sign(@Option(defaultValue = "JWT", description = "Status list token type JWT or CWT") String statusListTokenType) throws IOException, JOSEException, COSEException {
        StatusListToken statusListToken = StatusListToken.builder()
                .statusList(Objects.requireNonNull(statusList, "Status list not loaded"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(expires))
                .timeToLive(ttl)
                .subject(uri.toString())
                .keyId(keyId)
                .signingKey(signingKey)
                .build();
        if ("JWT".equalsIgnoreCase(statusListTokenType)) {
            Files.write(Paths.get(path, "status_list_token.jwt"), statusListToken.toSignedJWT().getBytes());
        } else if ("CWT".equalsIgnoreCase(statusListTokenType)) {
            Files.write(Paths.get(path, "status_list_token.cwt"), statusListToken.toSignedCWT().getBytes());
        } else {
            throw new IllegalArgumentException("Unsupported status list token type: " + statusListTokenType);
        }
        return "Status list token signed";
    }

    private StatusList getStatusList(String statusListEncoding) throws IOException {
        if ("JSON".equalsIgnoreCase(statusListEncoding)) {
            Path fullPath = Paths.get(path, "status_list.json");
            if (Files.exists(fullPath)) {
                return StatusList.buildFromJson().json(Files.readString(fullPath)).build();
            } else {
                throw new IllegalArgumentException("status_list.json not found");
            }
        } else if ("CBOR".equalsIgnoreCase(statusListEncoding)) {
            Path fullPath = Paths.get(path, "status_list.cbor");
            if (Files.exists(fullPath)) {
                return StatusList.buildFromCbor().cborHex(Files.readString(fullPath)).build();
            } else {
                throw new IllegalArgumentException("status_list.cbor not found");
            }
        } else {
            throw new IllegalArgumentException("Unsupported encoding: " + statusListEncoding);
        }
    }

    private void saveStatusList(StatusList statusList, String statusListEncoding) throws IOException {
        if ("JSON".equalsIgnoreCase(statusListEncoding)) {
            Map<String, Object> encoded = statusList.encodeAsMap(true);
            Files.write(Paths.get(path, "status_list.json"), objectMapper.writeValueAsString(encoded).getBytes());
        } else if ("CBOR".equalsIgnoreCase(statusListEncoding)) {
            Files.write(Paths.get(path, "status_list.cbor"), statusList.encodeAsCBORHex().getBytes());
        } else {
            throw new IllegalArgumentException("Unsupported encoding: " + statusListEncoding);
        }
    }
}
