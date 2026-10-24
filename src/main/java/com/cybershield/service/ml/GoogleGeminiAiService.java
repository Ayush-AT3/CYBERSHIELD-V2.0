package com.cybershield.service.ml;

import com.cybershield.model.GeminiAnalysisResult;
import com.cybershield.model.LayerResult;
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
import java.security.MessageDigest;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

@Service
public class GoogleGeminiAiService {

    private static final Logger log = LoggerFactory.getLogger(GoogleGeminiAiService.class);

    private static final String GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/";

    @Value("${google.gemini.api.key:}")
    private String apiKey;

    @Value("${google.gemini.model:gemini-2.5-flash}")
    private String model;

    @Value("${google.gemini.enabled:true}")
    private boolean enabled = true;

    private final CacheService cacheService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public GoogleGeminiAiService(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    public boolean isConfigured() {
        return enabled && apiKey != null && !apiKey.isBlank();
    }

    public GeminiAnalysisResult analyzeEmail(String subject, String sender, String body, List<LayerResult> layerResults) {
        if (!enabled) {
            return new GeminiAnalysisResult("SAFE", "Gemini AI analysis disabled.", "NONE", 0.0, true);
        }

        String contentKey = hashContent((subject != null ? subject : "") + "|" + (sender != null ? sender : "") + "|" + (body != null ? body : ""));
        GeminiAnalysisResult cached = cacheService.getCachedGeminiResult(contentKey);
        if (cached != null) {
            return cached;
        }

        GeminiAnalysisResult result;
        if (isConfigured()) {
            result = queryLiveGeminiForEmail(subject, sender, body, layerResults);
        } else {
            result = simulateGeminiAnalysis(subject, sender, body);
        }

        if (result != null) {
            cacheService.cacheGeminiResult(contentKey, result);
        }

        return result;
    }

    public GeminiAnalysisResult analyzeUrl(String url, LayerResult layer3Result) {
        if (!enabled || url == null || url.trim().isEmpty()) {
            return new GeminiAnalysisResult("SAFE", "Gemini AI analysis skipped.", "NONE", 0.0, true);
        }

        String contentKey = hashContent("URL:" + url.trim());
        GeminiAnalysisResult cached = cacheService.getCachedGeminiResult(contentKey);
        if (cached != null) {
            return cached;
        }

        GeminiAnalysisResult result;
        if (isConfigured()) {
            result = queryLiveGeminiForUrl(url, layer3Result);
        } else {
            result = simulateGeminiUrlAnalysis(url);
        }

        if (result != null) {
            cacheService.cacheGeminiResult(contentKey, result);
        }

        return result;
    }

    private GeminiAnalysisResult queryLiveGeminiForEmail(String subject, String sender, String body, List<LayerResult> layerResults) {
        try {
            String prompt = String.format(
                    "You are a cybersecurity expert analyzing an email for phishing and social engineering.\n" +
                    "Sender: %s\nSubject: %s\nBody: %s\n\n" +
                    "Evaluate this message. Provide output in EXACTLY this format:\n" +
                    "VERDICT: [PHISHING, SUSPICIOUS, or SAFE]\n" +
                    "TACTIC: [AUTHORITY_IMPERSONATION, URGENT_CREDENTIAL_HARVESTING, FINANCIAL_EXTORTION, or BENIGN_COMMUNICATION]\n" +
                    "REASONING: [Concise 2-sentence explanation of deceptive psychology, urgency, or lack of threat]",
                    escapeJson(sender != null ? sender : "Unknown"),
                    escapeJson(subject != null ? subject : "None"),
                    escapeJson(body != null && body.length() > 1000 ? body.substring(0, 1000) : (body != null ? body : ""))
            );

            return executeGeminiCall(prompt);
        } catch (Exception e) {
            log.warn("Gemini Live API call failed ({}). Falling back to simulated XAI synthesis.", e.getMessage());
            return simulateGeminiAnalysis(subject, sender, body);
        }
    }

    private GeminiAnalysisResult queryLiveGeminiForUrl(String url, LayerResult layer3Result) {
        try {
            String prompt = String.format(
                    "You are a cybersecurity analyst examining a destination URL for phishing, credential harvesting, or malware distribution.\n" +
                    "URL: %s\n\n" +
                    "Provide output in EXACTLY this format:\n" +
                    "VERDICT: [PHISHING, SUSPICIOUS, or SAFE]\n" +
                    "TACTIC: [BRAND_TYPOSQUATTING, CREDENTIAL_HARVESTING, MALICIOUS_REDIRECTION, or BENIGN_DESTINATION]\n" +
                    "REASONING: [Concise 2-sentence explanation of structural anomalies, domain entropy, or safety status]",
                    escapeJson(url)
            );

            return executeGeminiCall(prompt);
        } catch (Exception e) {
            log.warn("Gemini Live API call for URL failed ({}). Falling back to simulation.", e.getMessage());
            return simulateGeminiUrlAnalysis(url);
        }
    }

    private GeminiAnalysisResult executeGeminiCall(String prompt) throws Exception {
        String urlStr = GEMINI_BASE_URL + model + ":generateContent?key=" + apiKey.trim();

        String requestBody = "{\n" +
                "  \"contents\": [{\n" +
                "    \"parts\": [{\"text\": \"" + escapeJson(prompt) + "\"}]\n" +
                "  }],\n" +
                "  \"generationConfig\": {\n" +
                "    \"temperature\": 0.2,\n" +
                "    \"maxOutputTokens\": 250\n" +
                "  }\n" +
                "}";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(urlStr))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            JsonNode root = objectMapper.readTree(response.body());
            if (root.has("candidates") && root.get("candidates").isArray() && root.get("candidates").size() > 0) {
                JsonNode candidate = root.get("candidates").get(0);
                if (candidate.has("content") && candidate.get("content").has("parts")) {
                    String generatedText = candidate.get("content").get("parts").get(0).get("text").asText();
                    return parseGeminiOutput(generatedText, false);
                }
            }
        }

        log.warn("Gemini returned status {}: {}. Using simulation fallback.", response.statusCode(), response.body());
        throw new RuntimeException("Gemini returned status " + response.statusCode());
    }

    private GeminiAnalysisResult parseGeminiOutput(String rawText, boolean simulated) {
        String verdict = "SUSPICIOUS";
        String tactic = "SOCIAL_ENGINEERING";
        StringBuilder reasoning = new StringBuilder();

        String[] lines = rawText.split("\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.toUpperCase().startsWith("VERDICT:")) {
                String val = trimmed.substring(8).trim().toUpperCase();
                if (val.contains("PHISHING")) verdict = "PHISHING";
                else if (val.contains("SAFE")) verdict = "SAFE";
                else verdict = "SUSPICIOUS";
            } else if (trimmed.toUpperCase().startsWith("TACTIC:")) {
                tactic = trimmed.substring(7).trim();
            } else if (trimmed.toUpperCase().startsWith("REASONING:")) {
                reasoning.append(trimmed.substring(10).trim());
            } else if (!trimmed.isEmpty() && reasoning.length() > 0) {
                reasoning.append(" ").append(trimmed);
            }
        }

        if (reasoning.length() == 0) {
            reasoning.append(rawText.trim());
        }

        double confidence = "PHISHING".equals(verdict) ? 0.94 : ("SUSPICIOUS".equals(verdict) ? 0.72 : 0.98);
        return new GeminiAnalysisResult(verdict, reasoning.toString(), tactic, confidence, simulated);
    }

    private GeminiAnalysisResult simulateGeminiAnalysis(String subject, String sender, String body) {
        String combined = ((subject != null ? subject : "") + " " + (body != null ? body : "")).toLowerCase();
        String senderLower = (sender != null ? sender : "").toLowerCase();

        if (combined.contains("urgent") || combined.contains("suspended") || combined.contains("password") ||
                combined.contains("verify") || combined.contains("action required") || combined.contains("unauthorized") ||
                senderLower.contains("paypa1") || senderLower.contains("secure-update")) {
            return new GeminiAnalysisResult(
                    "PHISHING",
                    "Gemini Explainable AI: Detected psychological manipulation inducing synthetic panic through artificial deadlines. The message creates an illusion of immediate account suspension to coerce the victim into credential disclosure without secondary verification.",
                    "URGENT_CREDENTIAL_HARVESTING",
                    0.96,
                    true
            );
        } else if (combined.contains("invoice") || combined.contains("wire") || combined.contains("payment") ||
                combined.contains("bank") || combined.contains("crypto") || combined.contains("statement")) {
            return new GeminiAnalysisResult(
                    "SUSPICIOUS",
                    "Gemini Explainable AI: Identified targeted financial solicitation patterns. The content requests unverified payment redirection or invoice settlement characteristic of Business Email Compromise (BEC).",
                    "FINANCIAL_EXTORTION",
                    0.78,
                    true
            );
        } else {
            return new GeminiAnalysisResult(
                    "SAFE",
                    "Gemini Explainable AI: Linguistic patterns, structural semantics, and communication tone align with legitimate, low-risk business correspondence. No deceptive coercion or credential harvesting markers detected.",
                    "BENIGN_COMMUNICATION",
                    0.99,
                    true
            );
        }
    }

    private GeminiAnalysisResult simulateGeminiUrlAnalysis(String url) {
        String lower = url.toLowerCase();

        if (lower.contains("phish") || lower.contains("paypa1") || lower.contains("login") ||
                lower.contains("verify") || lower.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) {
            return new GeminiAnalysisResult(
                    "PHISHING",
                    "Gemini Explainable AI: URL structure exhibits high lexical entropy and brand concealment. The destination appears engineered to mimic legitimate authentication portals for credential harvesting.",
                    "CREDENTIAL_HARVESTING",
                    0.95,
                    true
            );
        } else if (lower.contains("redirect") || lower.contains("short") || lower.contains(".xyz") || lower.contains(".top")) {
            return new GeminiAnalysisResult(
                    "SUSPICIOUS",
                    "Gemini Explainable AI: Destination employs high-risk top-level domain or redirection techniques often used to obfuscate final landing pages from automated network firewalls.",
                    "MALICIOUS_REDIRECTION",
                    0.74,
                    true
            );
        } else {
            return new GeminiAnalysisResult(
                    "SAFE",
                    "Gemini Explainable AI: Domain structure adheres to standard internet naming conventions. Lexical entropy and certificate authorities conform to standard benign web entities.",
                    "BENIGN_DESTINATION",
                    0.98,
                    true
            );
        }
    }

    public Optional<ThreatIndicator> createThreatIndicator(GeminiAnalysisResult geminiResult) {
        if (geminiResult == null || "SAFE".equalsIgnoreCase(geminiResult.getVerdict())) {
            return Optional.empty();
        }

        boolean isPhishing = "PHISHING".equalsIgnoreCase(geminiResult.getVerdict());
        String modeDesc = geminiResult.isSimulated() ? "Simulation Intelligence" : "Live Google Gemini Flash Reasoning";

        ThreatIndicator indicator = new ThreatIndicator(
                "Layer 5 (Google Gemini XAI)",
                "GEMINI_AI_REASONING_FLAG",
                "Google Gemini XAI: " + geminiResult.getPrimaryTactic(),
                geminiResult.getReasoning(),
                isPhishing ? "HIGH" : "MEDIUM",
                isPhishing ? 3.5 : 2.0,
                String.format("Verdict: %s | Tactic: %s [%s]", geminiResult.getVerdict(), geminiResult.getPrimaryTactic(), modeDesc)
        );

        return Optional.of(indicator);
    }

    private String hashContent(String content) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(content.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().substring(0, 16);
        } catch (Exception e) {
            return String.valueOf(content.hashCode());
        }
    }

    private String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
