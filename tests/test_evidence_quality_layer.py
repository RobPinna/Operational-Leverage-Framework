import unittest

from app.services.evidence_quality_classifier import classify_evidence
from app.services.risk_story import _build_bundles_for_risk
from app.services.signal_model import compute_hypothesis_confidence


class EvidenceQualityLayerTests(unittest.TestCase):
    def test_generic_analytics_is_boilerplate(self):
        q = classify_evidence(
            url="https://www.googletagmanager.com/gtm.js?id=GTM-123",
            title="Script source",
            snippet="Google Tag Manager analytics pixel",
            source_type="html",
            connector="vendor_js_detection",
        )
        self.assertEqual(q.evidence_kind, "GENERIC_WEB")
        self.assertEqual(q.quality_tier, "BOILERPLATE")
        self.assertTrue(q.is_boilerplate)
        self.assertLessEqual(q.quality_weight, 0.15)

    def test_workflow_vendor_is_promoted(self):
        q = classify_evidence(
            url="https://js.stripe.com/v3/",
            title="Checkout script",
            snippet="Payment checkout integrated for billing flow",
            source_type="html",
            connector="vendor_js_detection",
        )
        self.assertEqual(q.evidence_kind, "WORKFLOW_VENDOR")
        self.assertIn(q.quality_tier, {"HIGH", "MED"})
        self.assertGreaterEqual(q.quality_weight, 0.70)
        self.assertFalse(q.is_boilerplate)

    def test_coverage_excludes_boilerplate(self):
        conf, meta = compute_hypothesis_confidence(
            [
                {
                    "url": "https://example.com/contact",
                    "snippet": "Contact us at support@example.com",
                    "signal_type": "CONTACT_CHANNEL",
                    "is_boilerplate": False,
                    "weight": 0.55,
                },
                {
                    "url": "https://www.googletagmanager.com/gtm.js",
                    "snippet": "analytics gtm tag manager",
                    "signal_type": "VENDOR_CUE",
                    "is_boilerplate": True,
                    "weight": 0.05,
                    "quality_tier": "BOILERPLATE",
                },
            ],
            base_avg=60,
            sector="Hospitality",
            risk_type="impersonation",
        )
        self.assertGreaterEqual(conf, 1)
        self.assertEqual(int(meta.get("signal_diversity_count", 0) or 0), 1)
        self.assertEqual(int(meta.get("weighted_evidence_count", 0) or 0), 1)

    def test_vendor_bundle_requires_workflow_vendor_kind(self):
        generic_vendor = [
            {
                "url": "https://www.googletagmanager.com/gtm.js",
                "canonical_url": "https://www.googletagmanager.com/gtm.js",
                "title": "GTM marker",
                "snippet": "Google Tag Manager marker",
                "signal_type": "VENDOR_CUE",
                "evidence_kind": "GENERIC_WEB",
                "is_boilerplate": True,
                "weight": 0.1,
            }
        ]
        bundles = _build_bundles_for_risk(
            evidence_valid=generic_vendor,
            counts={"VENDOR_CUE": 1},
            process_flags={},
        )
        types = {str(b.get("bundle_type", "")) for b in bundles}
        self.assertNotIn("VENDOR_DEPENDENCY", types)

        workflow_vendor = [
            {
                "url": "https://js.stripe.com/v3/",
                "canonical_url": "https://js.stripe.com/v3/",
                "title": "Stripe checkout",
                "snippet": "Checkout payment flow dependency",
                "signal_type": "VENDOR_CUE",
                "evidence_kind": "WORKFLOW_VENDOR",
                "is_boilerplate": False,
                "weight": 0.95,
            }
        ]
        bundles2 = _build_bundles_for_risk(
            evidence_valid=workflow_vendor,
            counts={"VENDOR_CUE": 1},
            process_flags={},
        )
        types2 = {str(b.get("bundle_type", "")) for b in bundles2}
        self.assertIn("VENDOR_DEPENDENCY", types2)


if __name__ == "__main__":
    unittest.main()
