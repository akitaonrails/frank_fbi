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

  # --- Domain poisoning defense ---

  test "filters out well-known domains (anti-poisoning)" do
    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => [], "url_domains" => ["microsoft.com", "evil.com", "apple.com", "google.com"] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["evil.com"], iocs[:domains]
  end

  test "filters well-known domains case-insensitively" do
    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => [], "url_domains" => ["Microsoft.COM", "evil.com"] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["evil.com"], iocs[:domains]
  end

  test "filters domain when all its scanned URLs are clean" do
    UrlScanResult.create!(
      url: "https://legit-business.com/about",
      source: "virustotal",
      malicious: false,
      detection_count: 0,
      scan_details: {},
      expires_at: 1.hour.from_now
    )
    UrlScanResult.create!(
      url: "https://legit-business.com/contact",
      source: "urlhaus",
      malicious: false,
      detection_count: 0,
      scan_details: {},
      expires_at: 1.hour.from_now
    )

    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => [], "url_domains" => ["legit-business.com", "evil.com"] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["evil.com"], iocs[:domains]
  end

  test "keeps domain when some scanned URLs are malicious" do
    UrlScanResult.create!(
      url: "https://suspicious.com/clean",
      source: "virustotal",
      malicious: false,
      detection_count: 0,
      scan_details: {},
      expires_at: 1.hour.from_now
    )
    UrlScanResult.create!(
      url: "https://suspicious.com/malware",
      source: "virustotal",
      malicious: true,
      detection_count: 3,
      scan_details: {},
      expires_at: 1.hour.from_now
    )

    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => [], "url_domains" => ["suspicious.com"] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_includes iocs[:domains], "suspicious.com"
  end

  test "keeps domain when no scan results exist" do
    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => [], "url_domains" => ["never-scanned.com"] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_includes iocs[:domains], "never-scanned.com"
  end

  # --- IP forgery defense ---

  test "filters Google MTA IPs" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "64.233.160.1" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_empty iocs[:ips]
  end

  test "filters Microsoft Exchange Online IPs" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "40.107.22.1" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_empty iocs[:ips]
  end

  test "allows real attacker IPs through" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "185.220.101.5" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["185.220.101.5"], iocs[:ips]
  end

  # --- SQL LIKE wildcard escaping (Issue 4) ---

  test "domain with SQL wildcard percent does not match unrelated URLs" do
    # Create a scan result for a completely different domain
    UrlScanResult.create!(
      url: "https://totally-different.com/page",
      source: "virustotal",
      malicious: false,
      detection_count: 0,
      scan_details: {},
      expires_at: 1.hour.from_now
    )

    # Domain with % wildcard — without escaping, "evil%clean" would LIKE-match
    # "https://totally-different.com/page" via the unescaped % acting as wildcard
    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => [], "url_domains" => ["evil%clean.com"] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    # The domain should NOT be filtered out — the clean scan is for a different domain
    assert_includes iocs[:domains], "evil%clean.com"
  end

  test "domain with SQL wildcard underscore does not match unrelated URLs" do
    UrlScanResult.create!(
      url: "https://evilXclean.com/page",
      source: "virustotal",
      malicious: false,
      detection_count: 0,
      scan_details: {},
      expires_at: 1.hour.from_now
    )

    create(:analysis_layer, :content_analysis, :completed,
      email: @email,
      details: { "urls" => [], "url_domains" => ["evil_clean.com"] }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    # Without escaping, _ matches any single char so "evil_clean" would match "evilXclean"
    assert_includes iocs[:domains], "evil_clean.com"
  end

  # --- CIDR precision tests (Issue 1: overly broad prefix matching) ---

  test "filters AWS CloudFront IP within CIDR range" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "13.32.100.5" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_empty iocs[:ips]
  end

  test "allows IP in 13.x range outside AWS CIDR blocks" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "13.1.2.3" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["13.1.2.3"], iocs[:ips]
  end

  test "allows IP in 52.x range outside AWS CIDR blocks" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "52.200.1.1" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["52.200.1.1"], iocs[:ips]
  end

  test "filters Cloudflare IP within 104.16.0.0/13" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "104.18.55.2" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_empty iocs[:ips]
  end

  test "allows IP in 104.x range outside Cloudflare CIDR" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "104.28.1.1" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["104.28.1.1"], iocs[:ips]
  end

  test "handles malformed IP address gracefully" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "sender_ip" => "not-an-ip" }
    )

    iocs = CommunityReporting::IocExtractor.new(@email).extract

    assert_equal ["not-an-ip"], iocs[:ips]
  end
end
