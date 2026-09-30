/*
   YARA Rule: HEALTHBANE Phishing PDF Detector
   Author: Nargiz Naghiyeva
   Description: Detects malicious PDF lure documents generated via wkhtmltopdf containing credential harvesting patterns.
   Date: 2026-09-30
   Reference: HEALTHBANE Campaign / MedDefense 4x00 Incident
   Threat Level: High
   Confidence: High
*/

rule HEALTHBANE_Phishing_PDF
{
    meta:
        author = "Nargiz Naghiyeva"
        description = "Detects HEALTHBANE campaign phishing PDF lures with embedded credential harvesting URLs"
        date = "2026-09-30"
        reference = "HEALTHBANE Campaign / MedDefense Task 9"
        threat_level = "High"
        confidence = "High"

    strings:
        // PDF Magic Bytes (Must start with %PDF)
        $pdf_magic = { 25 50 44 46 }

        // Creator / Tooling indicator observed in HEALTHBANE PDF phishing lures
        $tooling = "wkhtmltopdf" ascii wide nocase

        // Credential harvesting URI path fragments
        $path_login = "/login" ascii wide nocase
        $path_verify = "/verify" ascii wide nocase
        $path_portal = "/portal" ascii wide nocase
        $path_enroll = "/enroll" ascii wide nocase

        // Common URL parameter indicators for credential tracking
        $param_token = "token=" ascii wide nocase
        $param_id = "id=" ascii wide nocase

    condition:
        // 1. File must be a valid PDF (starts at offset 0 with %PDF)
        $pdf_magic at 0 and

        // 2. Must contain the specific generation tooling indicator
        $tooling and

        // 3. Must contain at least two credential-harvesting path/parameter patterns
        2 of ($path_login, $path_verify, $path_portal, $path_enroll, $param_token, $param_id)
}

/*
   =============================================================================
   TEST RESULTS DOCUMENTATION:
   =============================================================================
   Testing performed using local yara CLI against project sample corpus:

   $ yara 9-yara_phishing_pdf.yar samples/
   HEALTHBANE_Phishing_PDF samples/phishing_sample.pdf
   HEALTHBANE_Phishing_PDF samples/healthbane_lure_02.pdf

   - True Positives (MATCHED):
     * phishing_sample.pdf (Matches PDF magic, wkhtmltopdf, /login, token=)
     * healthbane_lure_02.pdf (Matches PDF magic, wkhtmltopdf, /portal, id=)

   - True Negatives (NOT MATCHED):
     * clean_invoice.pdf (Legitimate PDF without wkhtmltopdf or harvesting URLs)
     * benign_invoice.pdf (Standard PDF invoice without phishing indicators)
   =============================================================================
*/
