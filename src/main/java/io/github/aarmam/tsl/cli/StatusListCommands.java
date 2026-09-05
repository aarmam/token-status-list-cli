package io.github.aarmam.tsl.cli;

import com.authlete.cose.COSEException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import io.github.aarmam.tsl.StatusList;
import io.github.aarmam.tsl.StatusListAggregation;
import io.github.aarmam.tsl.StatusListToken;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.shell.command.annotation.Command;
import org.springframework.shell.command.annotation.Option;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Slf4j
@Command
@RequiredArgsConstructor
public class StatusListCommands {
    private final Key signingKey;
    private final X509Certificate signingCertificate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${status-list.path}")
    private String path;
    @Value("${status-list.uri}")
    private URI uri;
    @Value("${status-list.expires}")
    private Duration expires;
    @Value("${status-list.time-to-live}")
    private Duration ttl;
    @Value("${status-list.aggregation-uri:}")
    private String aggregationUri;
    @Value("${status-list.signing-eku-oid:}")
    private String signingEkuOid;
    @Value("${spring.ssl.bundle.pem.status-list-issuer.key.alias}")
    private String keyId;

    private StatusList statusList;

    @Command(command = "generate", description = "Generates the status list in specified format")
    public String generate(@Option(defaultValue = "1") Integer bits, @Option(defaultValue = "1048576") Integer size,
                           @Option(defaultValue = "JSON", description = "Status list encoding JSON or CBOR") String statusListEncoding,
                           @Option(description = "Status List Aggregation URI to embed in the list, overriding status-list.aggregation-uri") String aggregationUri) throws IOException {
        String uriToEmbed = StringUtils.hasText(aggregationUri) ? aggregationUri : this.aggregationUri;
        statusList = new StatusList(size, bits, StringUtils.hasText(uriToEmbed) ? uriToEmbed : null);
        saveStatusList(statusList, statusListEncoding);
        return "Status list token generated";
    }

    @Command(command = "aggregate", description = "Writes a Status List Aggregation listing the given Status List Token URIs")
    public String aggregate(@Option(description = "Comma separated Status List Token URIs; defaults to the configured status-list.uri")
                            String statusListUris) throws IOException {
        List<String> uris = StringUtils.hasText(statusListUris)
                ? Arrays.stream(statusListUris.split(",")).map(String::trim).filter(StringUtils::hasText).toList()
                : List.of(uri.toString());

        StatusListAggregation aggregation = StatusListAggregation.builder()
                .statusLists(uris)
                .build();
        Files.write(Paths.get(path, "status_list_aggregation.json"), aggregation.encodeAsJson().getBytes());

        return "Status list aggregation written with %d status list(s), serve it as %s"
                .formatted(uris.size(), StatusListAggregation.MEDIA_TYPE);
    }

    @Command(command = "load", alias = "l", description = "Loads the status list in JSON or CBOR Hex format")
    public String load(@Option(defaultValue = "JSON", description = "Status list encoding JSON or CBOR") String statusListEncoding) throws IOException {
        statusList = loadStatusList(statusListEncoding);

        Files.write(Paths.get(path, "status_list.txt"), statusList.printStatuses().getBytes());

        return "Status list loaded";
    }

    @Command(command = "save", description = "Saves the status list in JSON or CBOR Hex format")
    public String save(@Option(defaultValue = "JSON", description = "Status list encoding JSON or CBOR") String statusListEncoding) throws IOException {
        saveStatusList(statusList, statusListEncoding);
        return "Status list saved";
    }

    @Command(command = "get", alias = "g", description = "Gets the status at index")
    public String get(@Option @NonNull Integer index) {
        return "Status at index %d is %d".formatted(index, Objects.requireNonNull(statusList, "Status list not loaded").get(index));
    }

    @Command(command = "set", alias = "s", description = "Sets the status at index")
    public String set(@Option @NonNull Integer index, @Option @NonNull Integer status) {
        Objects.requireNonNull(statusList, "Status list not loaded").set(index, status);
        return "Status %d set at index %d".formatted(status, index);
    }

    @Command(command = "sign", description = "Generates and signs the status list token in specified format")
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
        warnIfSigningEkuMissing();

        if ("JWT".equalsIgnoreCase(statusListTokenType)) {
            Files.write(Paths.get(path, "status_list_token.jwt"), statusListToken.toSignedJWT().getBytes());
        } else if ("CWT".equalsIgnoreCase(statusListTokenType)) {
            // Section 8.2: an application/statuslist+cwt body is the raw binary encoding;
            // the hex in the specification's examples is for readability only. Sign once -
            // ECDSA is randomised, so signing twice would put a different token in each file.
            byte[] cwt = statusListToken.toSignedCWTBytes();
            Files.write(Paths.get(path, "status_list_token.cwt"), cwt);
            Files.write(Paths.get(path, "status_list_token.cwt.hex"), HexFormat.of().formatHex(cwt).getBytes());
        } else {
            throw new IllegalArgumentException("Unsupported status list token type: " + statusListTokenType);
        }
        return "Status list token signed";
    }

    /**
     * Warns when the signing certificate does not carry the extended key usage that
     * delegates Status List Token signing authority.
     * <p>
     * Section 10 defines id-kp-oauthStatusSigning for this, but its final OID arc is still
     * TBD in the draft, so the value to look for is configured rather than hardcoded. Set
     * status-list.signing-eku-oid once IANA assigns it to have the CLI check for it.
     */
    private void warnIfSigningEkuMissing() {
        if (!StringUtils.hasText(signingEkuOid) || signingCertificate == null) {
            return;
        }
        try {
            List<String> extendedKeyUsage = signingCertificate.getExtendedKeyUsage();
            if (extendedKeyUsage == null || !extendedKeyUsage.contains(signingEkuOid)) {
                log.warn("Signing certificate {} does not carry the status list signing EKU {}; " +
                                "a Relying Party enforcing Section 10 will reject tokens signed with it",
                        signingCertificate.getSubjectX500Principal(), signingEkuOid);
            }
        } catch (CertificateParsingException e) {
            log.warn("Could not read the extended key usage of the signing certificate", e);
        }
    }

    private StatusList loadStatusList(String statusListEncoding) throws IOException {
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
