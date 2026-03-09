require "test_helper"

class CommunityReporting::IocExtractorTest < ActiveSupport::TestCase
  setup do
    @email = create(:email, :spam,
      status: "completed",
      final_score: 92,
      verdict: "fraudulent",
      from_address: "scammer@evil-domain.com",
      sender_domain: "evil-domain.com"
    )
  end

  test "extracts URLs from content_analysis layer" do
    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => ["https://evil.com/phish", "https://malware.net/payload"], "url_domains" => ["evil.com", "malware.net"] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["https://evil.com/phish", "https://malware.net/payload"], iocs[:urls]
  end

  test "extracts domains from content_analysis layer" do
    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => [], "url_domains" => ["evil.com", "malware.net"] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_includes iocs[:domains], "evil.com"
    assert_includes iocs[:domains], "malware.net"
  end

  test "filters out freemail domains" do
    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => [], "url_domains" => ["gmail.com", "evil.com", "yahoo.com"] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["evil.com"], iocs[:domains]
  end

  test "extracts sender IP from header_auth layer" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "192.168.1.100" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["192.168.1.100"], iocs[:ips]
  end

  test "filters out cloud provider IPs" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "52.94.76.1" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_empty iocs[:ips]
  end

  test "extracts file hashes from external_api layer" do
    create(:analysis_layer, :external_api, :completed,
      email: @email,
      details: { "attachments" => [{ "sha256" => "abc123def456" }, { "sha256" => "789xyz000" }] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["abc123def456", "789xyz000"], iocs[:file_hashes]
  end

  test "filters out confirmed-clean URLs" do
    UrlScanResult.create!(
      url: "https://clean-site.com",
      source: "virustotal",
      malicious: false,
      detection_count: 0,
      scan_details: {},
      expires_at: 1.hour.from_now
    )

    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => ["https://clean-site.com", "https://evil.com/phish"], "url_domains" => [] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["https://evil.com/phish"], iocs[:urls]
  end

  test "includes sender email and domain" do
    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal "scammer@evil-domain.com", iocs[:sender_email]
    assert_equal "evil-domain.com", iocs[:sender_domain]
  end

  test "handles missing layers gracefully" do
    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_empty iocs[:urls]
    assert_empty iocs[:domains]
    assert_empty iocs[:ips]
    assert_empty iocs[:file_hashes]
  end

  test "limits URLs to 20" do
    urls = (1..25).map { |i| "https://evil#{i}.com" }
    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => urls, "url_domains" => [] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal 20, iocs[:urls].size
  end
end
