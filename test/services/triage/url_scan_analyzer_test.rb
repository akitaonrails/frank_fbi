require "test_helper"

class Triage::UrlScanAnalyzerTest < ActiveSupport::TestCase
  setup do
    @email = create(:email, :messenger_triage,
      extracted_urls: ["https://evil-phishing.com/login", "https://wa.me/551199999999", "https://safe-site.com"])

    # Stub all external services by default
    stub_request(:any, /urlhaus-api.abuse.ch/).to_return(
      status: 200,
      body: { query_status: "no_results" }.to_json,
      headers: { "Content-Type" => "application/json" }
    )
    stub_request(:any, /virustotal.com/).to_return(status: 200, body: "")
    stub_request(:any, /whoisxmlapi.com/).to_return(status: 200, body: "")
    stub_request(:any, //).to_timeout # catch-all for DNS lookups etc.
  end

  test "analyze creates triage_url_scan layer" do
    analyzer = Triage::UrlScanAnalyzer.new(@email)
    layer = analyzer.analyze

    assert_equal "triage_url_scan", layer.layer_name
    assert_equal "completed", layer.status
    assert_equal 0.40, layer.weight
  end

  test "malicious URL from URLhaus increases score" do
    stub_request(:post, "https://urlhaus-api.abuse.ch/v1/url/").to_return(
      status: 200,
      body: ->(request) {
        url = URI.decode_www_form(request.body).to_h["url"]
        if url == "https://evil-phishing.com/login"
          { query_status: "listed", threat: "malware_download" }.to_json
        else
          { query_status: "no_results" }.to_json
        end
      },
      headers: { "Content-Type" => "application/json" }
    )

    analyzer = Triage::UrlScanAnalyzer.new(@email)
    layer = analyzer.analyze

    assert layer.score > 0, "Score should increase for malicious URL"
    assert_includes layer.explanation, "ameaça"
    assert_equal 1, layer.details["urlhaus_malicious_count"]
  end

  test "no URLs produces low confidence" do
    email = create(:email, :messenger_triage, extracted_urls: [])

    analyzer = Triage::UrlScanAnalyzer.new(email)
    layer = analyzer.analyze

    assert_equal 0, layer.score
    assert_equal 0.3, layer.confidence
    assert_includes layer.explanation, "Nenhuma URL"
  end

  test "scans up to 25 URLs" do
    urls = (1..30).map { |i| "https://example#{i}.com" }
    email = create(:email, :messenger_triage, extracted_urls: urls)

    call_count = 0
    stub_request(:post, "https://urlhaus-api.abuse.ch/v1/url/").to_return(
      status: 200,
      body: ->(_) { call_count += 1; { query_status: "no_results" }.to_json },
      headers: { "Content-Type" => "application/json" }
    )

    Triage::UrlScanAnalyzer.new(email).analyze

    assert_equal 25, call_count, "Should scan at most 25 URLs via URLhaus"
  end
end
