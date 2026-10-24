package com.cybershield;

import com.cybershield.model.GeminiAnalysisResult;
import com.cybershield.model.ThreatIndicator;
import com.cybershield.service.cache.CacheService;
import com.cybershield.service.ml.GoogleGeminiAiService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class GoogleGeminiAiServiceTest {

    private GoogleGeminiAiService geminiAiService;
    private CacheService cacheService;

    @BeforeEach
    public void setUp() {
        cacheService = new CacheService();
        geminiAiService = new GoogleGeminiAiService(cacheService);
    }

    @Test
    public void testBenignEmailAnalysis() {
        String subject = "Project Sync Meeting Notes";
        String sender = "sarah.manager@company.com";
        String body = "Hi team, attached are the minutes from today's quarterly sprint planning. Great progress everyone!";

        GeminiAnalysisResult result = geminiAiService.analyzeEmail(subject, sender, body, Collections.emptyList());

        assertNotNull(result);
        assertEquals("SAFE", result.getVerdict());
        assertEquals("BENIGN_COMMUNICATION", result.getPrimaryTactic());
        assertNotNull(result.getReasoning());
        assertTrue(result.getReasoning().contains("Gemini"));
    }

    @Test
    public void testUrgentPhishingEmailAnalysis() {
        String subject = "URGENT: Your Bank Account Has Been Suspended!";
        String sender = "security@paypa1-update.com";
        String body = "Immediate action required: Unauthorized login detected. Verify your password now or account will be closed.";

        GeminiAnalysisResult result = geminiAiService.analyzeEmail(subject, sender, body, Collections.emptyList());

        assertNotNull(result);
        assertEquals("PHISHING", result.getVerdict());
        assertEquals("URGENT_CREDENTIAL_HARVESTING", result.getPrimaryTactic());
        assertTrue(result.getReasoning().contains("panic") || result.getReasoning().contains("manipulation"));

        Optional<ThreatIndicator> indicatorOpt = geminiAiService.createThreatIndicator(result);
        assertTrue(indicatorOpt.isPresent());
        ThreatIndicator indicator = indicatorOpt.get();
        assertEquals("HIGH", indicator.getSeverity());
        assertEquals(3.5, indicator.getScoreContribution());
        assertTrue(indicator.getTitle().contains("Google Gemini XAI"));
    }

    @Test
    public void testSuspiciousFinancialEmailAnalysis() {
        String subject = "Overdue Invoice Payment Wire Confirmation";
        String sender = "billing-department@vendor-redirect.com";
        String body = "Please review attached payment statement and confirm wire transfer routing details immediately.";

        GeminiAnalysisResult result = geminiAiService.analyzeEmail(subject, sender, body, Collections.emptyList());

        assertNotNull(result);
        assertEquals("SUSPICIOUS", result.getVerdict());
        assertEquals("FINANCIAL_EXTORTION", result.getPrimaryTactic());
    }

    @Test
    public void testUrlAnalysisPhishingVerdict() {
        String url = "http://paypa1-security-login-verify.com";

        GeminiAnalysisResult result = geminiAiService.analyzeUrl(url, null);

        assertNotNull(result);
        assertEquals("PHISHING", result.getVerdict());
        assertEquals("CREDENTIAL_HARVESTING", result.getPrimaryTactic());
    }
}
