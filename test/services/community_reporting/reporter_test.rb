require "test_helper"

class CommunityReporting::ReporterTest < ActiveSupport::TestCase
  setup do
    # No API keys set — all providers should be skipped silently
    ENV["THREATFOX_AUTH_KEY"] = ""
    ENV["ABUSEIPDB_API_KEY"] = ""
    ENV["SPAMCOP_SUBMISSION_ADDRESS"] = ""

    @email = create(:email, :spam,
      status: "completed",
      final_score: 92,
      verdict: "fraudulent",
      pipeline_type: "fraud_analysis"
    )

    # Add analysis layers with IOC data
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "192.168.1.100" }
    )
    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => ["https://evil.com/phish"], "url_domains" => ["evil.com"] }
    )
    create(:analysis_layer, :external_api, :completed,
      email: @email,
      details: { "attachments" => [] }
    )
  end

  teardown do
    ENV["THREATFOX_AUTH_KEY"] = ""
    ENV["ABUSEIPDB_API_KEY"] = ""
    ENV["SPAMCOP_SUBMISSION_ADDRESS"] = ""
  end

  # Eligibility tests

  test "eligible when fraudulent with score >= 85" do
    reporter = CommunityReporting::Reporter.new(@email)

    assert reporter.eligible?
  end

  test "not eligible when verdict is not fraudulent" do
    @email.update!(verdict: "suspicious_likely_fraud", final_score: 70)
    reporter = CommunityReporting::Reporter.new(@email)

    assert_not reporter.eligible?
  end

  test "not eligible when score below 85" do
    @email.update!(final_score: 84)
    reporter = CommunityReporting::Reporter.new(@email)

    assert_not reporter.eligible?
  end

  test "not eligible for messenger_triage pipeline" do
    @email.update!(pipeline_type: "messenger_triage")
    reporter = CommunityReporting::Reporter.new(@email)

    assert_not reporter.eligible?
  end

  test "not eligible when already reported" do
    CommunityReport.create!(
      email: @email,
      iocs_submitted: {},
      providers: [],
      details: {}
    )
    reporter = CommunityReporting::Reporter.new(@email)

    assert_not reporter.eligible?
  end

  test "not eligible when final_score is nil" do
    @email.update_columns(final_score: nil)
    reporter = CommunityReporting::Reporter.new(@email)

    assert_not reporter.eligible?
  end

  # Reporting tests

  test "report creates community_report audit record" do
    reporter = CommunityReporting::Reporter.new(@email)

    assert_difference "CommunityReport.count", 1 do
      reporter.report
    end

    record = CommunityReport.find_by(email: @email)
    assert_not_nil record
    assert_equal 1, record.iocs_submitted["url_count"]
    assert_equal 1, record.iocs_submitted["domain_count"]
    assert_equal 1, record.iocs_submitted["ip_count"]
  end

  test "report skips all providers when no API keys set" do
    reporter = CommunityReporting::Reporter.new(@email)
    results = reporter.report

    assert_not_nil results
    # All providers skipped (returned nil)
    assert_nil results[:threatfox]
    assert_nil results[:abuseipdb]
    assert_nil results[:spamcop]
  end

  test "report does not run when not eligible" do
    @email.update!(verdict: "legitimate", final_score: 10)
    reporter = CommunityReporting::Reporter.new(@email)

    assert_no_difference "CommunityReport.count" do
      result = reporter.report
      assert_nil result
    end
  end

  test "report is idempotent — second call does nothing" do
    reporter = CommunityReporting::Reporter.new(@email)

    reporter.report
    assert_no_difference "CommunityReport.count" do
      result = reporter.report
      assert_nil result
    end
  end

  test "report logs providers that returned results" do
    ENV["THREATFOX_AUTH_KEY"] = "test-key"

    stub_request(:post, "https://threatfox-api.abuse.ch/api/v1/")
      .to_return(
        status: 200,
        body: { query_status: "ok", data: nil }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    reporter = CommunityReporting::Reporter.new(@email)
    reporter.report

    record = CommunityReport.find_by(email: @email)
    assert_includes record.providers, "threatfox"
  end

  test "report skips abuseipdb when no IPs extracted" do
    # Remove the header_auth layer that has sender_ip
    @email.analysis_layers.find_by(layer_name: "header_auth").destroy

    reporter = CommunityReporting::Reporter.new(@email)
    results = reporter.report

    assert_not results.key?(:abuseipdb)
  end
end
