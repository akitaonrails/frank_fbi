require "test_helper"

class CommunityReporting::AbuseipdbClientTest < ActiveSupport::TestCase
  setup do
    ENV["ABUSEIPDB_API_KEY"] = "test-abuseipdb-key"
    @client = CommunityReporting::AbuseipdbClient.new
  end

  teardown do
    ENV["ABUSEIPDB_API_KEY"] = ""
  end

  test "returns nil when API key is blank" do
    ENV["ABUSEIPDB_API_KEY"] = ""
    client = CommunityReporting::AbuseipdbClient.new

    assert_nil client.report_ip("192.168.1.100")
  end

  test "returns nil when IP is blank" do
    assert_nil @client.report_ip("")
    assert_nil @client.report_ip(nil)
  end

  test "reports IP to AbuseIPDB API" do
    stub_request(:post, "https://api.abuseipdb.com/api/v2/report")
      .with(headers: { "Key" => "test-abuseipdb-key", "Accept" => "application/json" })
      .to_return(
        status: 200,
        body: { data: { abuseConfidenceScore: 85 } }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    result = @client.report_ip("192.168.1.100", comment: "Test phishing email")

    assert_not_nil result
    assert_equal "192.168.1.100", result[:ip]
    assert_equal 85, result[:abuse_confidence_score]
  end

  test "uses default categories" do
    stub_request(:post, "https://api.abuseipdb.com/api/v2/report")
      .to_return(
        status: 200,
        body: { data: { abuseConfidenceScore: 50 } }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    @client.report_ip("192.168.1.100")

    assert_requested(:post, "https://api.abuseipdb.com/api/v2/report") do |req|
      body = URI.decode_www_form(req.body).to_h
      body["categories"] == "11,9"
    end
  end

  test "returns nil on API error" do
    stub_request(:post, "https://api.abuseipdb.com/api/v2/report")
      .to_return(status: 429)

    assert_nil @client.report_ip("192.168.1.100")
  end

  test "handles network exception gracefully" do
    stub_request(:post, "https://api.abuseipdb.com/api/v2/report")
      .to_raise(Errno::ECONNREFUSED)

    assert_nil @client.report_ip("192.168.1.100")
  end

  test "truncates long comments" do
    stub_request(:post, "https://api.abuseipdb.com/api/v2/report")
      .to_return(
        status: 200,
        body: { data: { abuseConfidenceScore: 50 } }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    long_comment = "x" * 2000
    @client.report_ip("192.168.1.100", comment: long_comment)

    assert_requested(:post, "https://api.abuseipdb.com/api/v2/report") do |req|
      body = URI.decode_www_form(req.body).to_h
      body["comment"].length <= 1024
    end
  end
end
