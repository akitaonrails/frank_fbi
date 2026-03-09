require "test_helper"

class BraveSearchClientTest < ActiveSupport::TestCase
  setup do
    @client = BraveSearchClient.new
    ENV["BRAVE_SEARCH_API_KEY"] = "test-key"
  end

  teardown do
    ENV["BRAVE_SEARCH_API_KEY"] = ""
  end

  test "returns nil when API key is blank" do
    ENV["BRAVE_SEARCH_API_KEY"] = ""
    client = BraveSearchClient.new
    assert_nil client.search("test query")
  end

  test "returns cached result if available" do
    cache_key = "brave:#{Digest::SHA256.hexdigest("FBI agent John Smith")}"
    UrlScanResult.create!(
      url: cache_key,
      source: "brave_search",
      malicious: false,
      detection_count: 3,
      scan_details: {
        "query" => "FBI agent John Smith",
        "results" => [
          { "title" => "FBI Careers", "url" => "https://fbi.gov/careers", "description" => "Join the FBI" }
        ]
      },
      expires_at: 1.day.from_now
    )

    result = @client.search("FBI agent John Smith")
    assert_equal "brave_search", result[:source]
    assert result[:cached]
    assert_equal 1, result[:results].size
  end

  test "does not return expired cache" do
    cache_key = "brave:#{Digest::SHA256.hexdigest("expired query")}"
    UrlScanResult.create!(
      url: cache_key,
      source: "brave_search",
      malicious: false,
      scan_details: { "results" => [] },
      expires_at: 1.day.ago
    )

    stub_request(:get, /api.search.brave.com/)
      .to_return(status: 200, body: { web: { results: [] } }.to_json)

    result = @client.search("expired query")
    assert_not result[:cached]
  end

  test "parses API response correctly" do
    stub_request(:get, /api.search.brave.com/)
      .to_return(
        status: 200,
        body: {
          web: {
            results: [
              {
                title: "John Smith - LinkedIn",
                url: "https://linkedin.com/in/john-smith",
                description: "John Smith is a software engineer",
                age: "2 years ago",
                meta_url: { hostname: "linkedin.com" }
              },
              {
                title: "John Smith | Company",
                url: "https://example.com/team/john",
                description: "Meet our team member John Smith"
              }
            ]
          }
        }.to_json
      )

    result = @client.search("John Smith software engineer")
    assert_equal "brave_search", result[:source]
    assert_equal 2, result[:results].size
    assert_equal "John Smith - LinkedIn", result[:results].first[:title]
    assert_equal "linkedin.com", result[:results].first[:site_name]
  end

  test "caches successful results" do
    stub_request(:get, /api.search.brave.com/)
      .to_return(
        status: 200,
        body: { web: { results: [{ title: "Test", url: "https://example.com", description: "Test result" }] } }.to_json
      )

    assert_difference "UrlScanResult.count", 1 do
      @client.search("cache test query")
    end

    cached = UrlScanResult.last
    assert_equal "brave_search", cached.source
    assert cached.expires_at > 6.days.from_now
  end

  test "returns nil on API error" do
    stub_request(:get, /api.search.brave.com/)
      .to_return(status: 500, body: "Internal Server Error")

    assert_nil @client.search("failing query")
  end

  test "returns nil on network error" do
    stub_request(:get, /api.search.brave.com/)
      .to_raise(Net::OpenTimeout)

    assert_nil @client.search("timeout query")
  end
end
