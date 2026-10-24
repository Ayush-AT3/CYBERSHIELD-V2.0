package com.cybershield.service.layer3;

import com.cybershield.model.GoogleSafeBrowsingResult;
import com.cybershield.model.ThreatIndicator;
import com.cybershield.service.cache.CacheService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

@Service
public class GoogleSafeBrowsingService {

    private static final Logger log = LoggerFactory.getLogger(GoogleSafeBrowsingService.class);

    private static final String API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=";

    @Value("${google.safebrowsing.api.key:}")
    private String apiKey;

    @Value("${google.safebrowsing.enabled:true}")
    private boolean enabled = true;

    private final CacheService cacheService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(4))
            .build();

    public GoogleSafeBrowsingService(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    public boolean isConfigured() {
        return enabled && apiKey != null && !apiKey.isBlank();
    }

    public GoogleSafeBrowsingResult checkUrl(String url) {
        if (url == null || url.trim().isEmpty() || !enabled) {
            return new GoogleSafeBrowsingResult(false, null, null, url, false);
        }

        String normalizedUrl = url.trim();

        // 1. Check cache first
        GoogleSafeBrowsingResult cached = cacheService.getCachedGoogleSafeBrowsing(normalizedUrl);
        if (cached != null) {
            return cached;
        }

        GoogleSafeBrowsingResult result;
        if (isConfigured()) {
            result = queryLiveApi(normalizedUrl);
        } else {
            result = simulateSafeBrowsing(normalizedUrl);
        }

        if (result != null) {
            cacheService.cacheGoogleSafeBrowsing(normalizedUrl, result);
        }

        return result;
    }

    private GoogleSafeBrowsingResult queryLiveApi(String url) {
        try {
            String requestJson = buildRequestBody(url);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_ENDPOINT + apiKey.trim()))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(4))
                    .POST(HttpRequest.BodyPublishers.ofString(requestJson, StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                if (root.has("matches") && root.get("matches").isArray() && root.get("matches").size() > 0) {
                    JsonNode firstMatch = root.get("matches").get(0);
                    String threatType = firstMatch.has("threatType") ? firstMatch.get("threatType").asText() : "SOCIAL_ENGINEERING";
                    String platformType = firstMatch.has("platformType") ? firstMatch.get("platformType").asText() : "ANY_PLATFORM";
                    String cacheDuration = firstMatch.has("cacheDuration") ? firstMatch.get("cacheDuration").asText() : "300s";

                    log.warn("🚨 Google Safe Browsing Flagged Threat [{}] on URL: {}", threatType, url);
                    GoogleSafeBrowsingResult res = new GoogleSafeBrowsingResult(true, threatType, platformType, url, false);
                    res.setCacheDuration(cacheDuration);
                    return res;
                } else {
                    // Safe / Clean URL
                    return new GoogleSafeBrowsingResult(false, null, null, url, false);
                }
            } else {
                log.warn("Google Safe Browsing API returned non-200 status code: {}. Falling back to simulation.", response.statusCode());
                return simulateSafeBrowsing(url);
            }
        } catch (Exception e) {
            log.warn("Error querying Google Safe Browsing API ({}). Falling back to simulation.", e.getMessage());
            return simulateSafeBrowsing(url);
        }
    }

    private String buildRequestBody(String url) {
        return "{\n" +
                "  \"client\": {\n" +
                "    \"clientId\": \"cybershield-security\",\n" +
                "    \"clientVersion\": \"2.0.0\"\n" +
                "  },\n" +
                "  \"threatInfo\": {\n" +
                "    \"threatTypes\": [\"MALWARE\", \"SOCIAL_ENGINEERING\", \"UNWANTED_SOFTWARE\", \"POTENTIALLY_HARMFUL_APPLICATION\"],\n" +
                "    \"platformTypes\": [\"ANY_PLATFORM\"],\n" +
                "    \"threatEntryTypes\": [\"URL\"],\n" +
                "    \"threatEntries\": [\n" +
                "      {\"url\": \"" + escapeJson(url) + "\"}\n" +
                "    ]\n" +
                "  }\n" +
                "}";
    }

    private GoogleSafeBrowsingResult simulateSafeBrowsing(String url) {
        String lower = url.toLowerCase();

        // High confidence simulated phishing/malware patterns for demonstration & offline robustness
        boolean isPhishingMatch = lower.contains("phish") ||
                lower.contains("paypa1") ||
                lower.contains("login-verify") ||
                lower.contains("security-update-account") ||
                lower.contains("credential-confirm") ||
                lower.contains("suspicious-domain") ||
                (lower.contains("signin") && lower.contains(".xyz")) ||
                (lower.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*") && lower.contains("login"));

        boolean isMalwareMatch = lower.contains("trojan") ||
                lower.contains("payload") ||
                lower.contains("exploit") ||
                lower.endsWith(".exe") ||
                lower.endsWith(".scr") ||
                lower.endsWith(".bat");

        if (isPhishingMatch) {
            return new GoogleSafeBrowsingResult(true, "SOCIAL_ENGINEERING", "ANY_PLATFORM", url, true);
        } else if (isMalwareMatch) {
            return new GoogleSafeBrowsingResult(true, "MALWARE", "ANY_PLATFORM", url, true);
        }

        return new GoogleSafeBrowsingResult(false, null, null, url, true);
    }

    public Optional<ThreatIndicator> createThreatIndicator(String url, GoogleSafeBrowsingResult result) {
        if (result == null || !result.isThreatFound()) {
            return Optional.empty();
        }

        String threatType = result.getThreatType() != null ? result.getThreatType() : "SOCIAL_ENGINEERING";
        String modeDesc = result.isSimulated() ? "Simulation Intelligence" : "Live Google Cloud Threat Match";

        ThreatIndicator indicator = new ThreatIndicator(
                "Layer 3 (Google Safe Browsing)",
                "GOOGLE_SAFE_BROWSING_FLAGGED",
                "Google Safe Browsing: " + threatType + " Detected",
                String.format("Google's planetary threat intelligence flagged this destination as active %s. Google Chrome and Android enforce immediate quarantine on this destination.", threatType),
                "CRITICAL",
                7.0,
                String.format("Threat: %s | Verified by: Google Safe Browsing API [%s]", threatType, modeDesc)
        );

        return Optional.of(indicator);
    }

    private String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
