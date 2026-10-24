package com.cybershield;

import com.cybershield.model.GoogleSafeBrowsingResult;
import com.cybershield.model.ThreatIndicator;
import com.cybershield.service.cache.CacheService;
import com.cybershield.service.layer3.GoogleSafeBrowsingService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class GoogleSafeBrowsingServiceTest {

    private GoogleSafeBrowsingService safeBrowsingService;
    private CacheService cacheService;

    @BeforeEach
    public void setUp() {
        cacheService = new CacheService();
        safeBrowsingService = new GoogleSafeBrowsingService(cacheService);
    }

    @Test
    public void testCleanUrlReturnsNoThreat() {
        String cleanUrl = "https://www.wikipedia.org/wiki/Computer_security";
        GoogleSafeBrowsingResult result = safeBrowsingService.checkUrl(cleanUrl);

        assertNotNull(result);
        assertFalse(result.isThreatFound());
    }

    @Test
    public void testSimulatedPhishingUrlFlagged() {
        String phishingUrl = "http://paypa1-security-update-account.com/login.php";
        GoogleSafeBrowsingResult result = safeBrowsingService.checkUrl(phishingUrl);

        assertNotNull(result);
        assertTrue(result.isThreatFound());
        assertEquals("SOCIAL_ENGINEERING", result.getThreatType());

        Optional<ThreatIndicator> indicatorOpt = safeBrowsingService.createThreatIndicator(phishingUrl, result);
        assertTrue(indicatorOpt.isPresent());
        ThreatIndicator indicator = indicatorOpt.get();
        assertEquals("CRITICAL", indicator.getSeverity());
        assertEquals(7.0, indicator.getScoreContribution());
        assertTrue(indicator.getTitle().contains("Global Threat Intelligence"));
    }

    @Test
    public void testSimulatedMalwarePayloadUrlFlagged() {
        String malwareUrl = "http://malicious-files-storage.com/invoice.pdf.exe";
        GoogleSafeBrowsingResult result = safeBrowsingService.checkUrl(malwareUrl);

        assertNotNull(result);
        assertTrue(result.isThreatFound());
        assertEquals("MALWARE", result.getThreatType());
    }

    @Test
    public void testCachingPreventsDuplicateCalls() {
        String testUrl = "http://login-verify-account.xyz/test";
        GoogleSafeBrowsingResult first = safeBrowsingService.checkUrl(testUrl);
        GoogleSafeBrowsingResult second = safeBrowsingService.checkUrl(testUrl);

        assertNotNull(first);
        assertNotNull(second);
        assertEquals(first.isThreatFound(), second.isThreatFound());
    }
}
