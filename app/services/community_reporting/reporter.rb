module CommunityReporting
  class Reporter
    MINIMUM_SCORE = 85
    REQUIRED_VERDICT = "fraudulent"

    def initialize(email)
      @email = email
    end

    def eligible?
      @email.verdict == REQUIRED_VERDICT &&
        @email.final_score.present? &&
        @email.final_score >= MINIMUM_SCORE &&
        @email.pipeline_type == "fraud_analysis" &&
        !already_reported?
    end

    def report
      return unless eligible?

      iocs = IocExtractor.new(@email).extract
      results = {}

      results[:threatfox] = ThreatfoxClient.new.submit_iocs(
        iocs,
        confidence: @email.final_score,
        reference: "Frank FBI automated analysis"
      )

      if iocs[:ips].any?
        results[:abuseipdb] = AbuseipdbClient.new.report_ip(
          iocs[:ips].first,
          comment: "Phishing/fraud email detected by automated analysis (score: #{@email.final_score}/100)"
        )
      end

      results[:spamcop] = SpamcopForwarder.new.forward(@email)

      log_report(iocs, results)
      results
    end

    private

    def already_reported?
      CommunityReport.exists?(email: @email)
    end

    def log_report(iocs, results)
      CommunityReport.create!(
        email: @email,
        iocs_submitted: {
          url_count: iocs[:urls].size,
          domain_count: iocs[:domains].size,
          ip_count: iocs[:ips].size,
          hash_count: iocs[:file_hashes].size,
          sender_email: iocs[:sender_email],
          sender_domain: iocs[:sender_domain]
        },
        providers: results.keys.select { |k| results[k].present? }.map(&:to_s),
        details: results.transform_values { |v| v || "skipped" }
      )
    end
  end
end
