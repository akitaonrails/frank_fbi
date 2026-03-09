require "test_helper"

class CommunityReporting::ThreatfoxClientTest < ActiveSupport::TestCase
  setup do
    ENV["THREATFOX_AUTH_KEY"] = "test-threatfox-key"
    @client = CommunityReporting::ThreatfoxClient.new
    @iocs = {
      urls: ["https://evil.com/phish"],
      domains: ["evil.com"],
      ips: ["192.168.1.100"],
      file_hashes: [],
      sender_email: "scammer@evil.com",
      sender_domain: "evil.com"
    }
  end

  teardown do
    ENV["THREATFOX_AUTH_KEY"] = ""
  end

  test "returns nil when API key is blank" do
    ENV["THREATFOX_AUTH_KEY"] = ""
    client = CommunityReporting::ThreatfoxClient.new

    assert_nil client.submit_iocs(@iocs, confidence: 90)
  end

  test "submits IOCs to ThreatFox API" do
    stub_request(:post, "https://threatfox-api.abuse.ch/api/v1/")
      .with(headers: { "Auth-Key" => "test-threatfox-key", "Content-Type" => "application/json" })
      .to_return(
        status: 200,
        body: { query_status: "ok", data: nil }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    results = @client.submit_iocs(@iocs, confidence: 90)

    assert_not_nil results
    assert results.is_a?(Array)
  end

  test "returns nil when no IOCs to submit" do
    empty_iocs = { urls: [], domains: [], ips: [], file_hashes: [] }

    assert_nil @client.submit_iocs(empty_iocs, confidence: 90)
  end

  test "returns nil on API error" do
    stub_request(:post, "https://threatfox-api.abuse.ch/api/v1/")
      .to_return(status: 500)

    results = @client.submit_iocs(@iocs, confidence: 90)

    assert results.is_a?(Array)
    assert results.all?(&:nil?)
  end

  test "handles network exception gracefully" do
    stub_request(:post, "https://threatfox-api.abuse.ch/api/v1/")
      .to_raise(Errno::ECONNREFUSED)

    assert_nil @client.submit_iocs(@iocs, confidence: 90)
  end

  test "maps confidence correctly" do
    stub_request(:post, "https://threatfox-api.abuse.ch/api/v1/")
      .to_return(
        status: 200,
        body: { query_status: "ok", data: nil }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    @client.submit_iocs(@iocs, confidence: 95, reference: "test ref")

    assert_requested(:post, "https://threatfox-api.abuse.ch/api/v1/") do |req|
      body = JSON.parse(req.body)
      body["confidence_level"] == 95
    end
  end
end
