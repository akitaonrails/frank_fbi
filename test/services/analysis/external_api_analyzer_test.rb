require "test_helper"

class Analysis::ExternalApiAnalyzerTest < ActiveSupport::TestCase
  # Fake DNS resolver for testing blacklist lookups
  class FakeDnsResolver
    def initialize(listed_domains: [], all_listed: false)
      @listed_domains = listed_domains
      @all_listed = all_listed
    end

    def timeouts=(val); end
    def close; end

    def getaddresses(query)
      if @all_listed || @listed_domains.any? { |d| query.include?(d) }
        [Resolv::IPv4.create("127.0.0.2")]
      else
        []
      end
    end
  end

  setup do
    ENV["VIRUSTOTAL_API_KEY"] = "test-api-key"
    ENV["WHOISXML_API_KEY"] = "test-whois-key"

    # Stub all external APIs to return benign by default
    stub_request(:post, "https://urlhaus-api.abuse.ch/v1/url/").to_return(
      status: 200,
      body: { query_status: "no_results" }.to_json,
      headers: { "Content-Type" => "application/json" }
    )
    stub_request(:post, "https://urlhaus-api.abuse.ch/v1/host/").to_return(
      status: 200,
      body: { urls_online: 0 }.to_json,
      headers: { "Content-Type" => "application/json" }
    )
    stub_request(:post, /www\.virustotal\.com\/api\/v3\/urls/).to_return(status: 404)
    stub_request(:get, /www\.virustotal\.com\/api\/v3\/analyses/).to_return(status: 404)
    stub_request(:get, /www\.virustotal\.com\/api\/v3\/files/).to_return(status: 404)
    stub_request(:get, /whoisxmlapi\.com/).to_return(status: 404)

    # Replace Resolv::DNS.new with a fake that returns "not listed" by default
    @original_dns_new = Resolv::DNS.method(:new)
    @fake_dns = FakeDnsResolver.new
    Resolv::DNS.define_singleton_method(:new) { |**_| @fake_dns_instance }
    Resolv::DNS.instance_variable_set(:@fake_dns_instance, @fake_dns)
    Resolv::DNS.define_singleton_method(:new) { Resolv::DNS.instance_variable_get(:@fake_dns_instance) }
  end

  teardown do
    ENV["VIRUSTOTAL_API_KEY"] = ""
    ENV["WHOISXML_API_KEY"] = ""

    # Restore original Resolv::DNS.new
    original = @original_dns_new
    Resolv::DNS.define_singleton_method(:new) { |**kwargs| original.call(**kwargs) }
  end

  # --- URL domain WHOIS checks ---

  test "flags young URL domain under 30 days" do
    email = create(:email, extracted_urls: ["https://phishing-site.live/login"], sender_domain: "example.com")

    stub_whois_api("phishing-site.live", 5.days.ago.iso8601)

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert_equal "completed", layer.status
    assert layer.score >= 20, "Young domain (<30d) should add +20, got #{layer.score}"
    domains = get_details(layer, "url_domains")
    assert domains.any? { |d| get(d, "domain") == "phishing-site.live" && get(d, "young") }
  end

  test "flags URL domain between 30 and 90 days" do
    email = create(:email, extracted_urls: ["https://new-domain.xyz/page"], sender_domain: "example.com")

    stub_whois_api("new-domain.xyz", 60.days.ago.iso8601)

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert layer.score >= 10, "Young domain (30-90d) should add +10, got #{layer.score}"
  end

  test "flags blacklisted URL domain" do
    email = create(:email, extracted_urls: ["https://malicious-site.com/payload"], sender_domain: "example.com")

    stub_whois_api("malicious-site.com", 1.year.ago.iso8601)
    set_dns_fake(FakeDnsResolver.new(listed_domains: ["malicious-site.com"]))

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert layer.score >= 15, "Blacklisted domain should add score, got #{layer.score}"
    domains = get_details(layer, "url_domains")
    assert domains.any? { |d| get(d, "domain") == "malicious-site.com" && get(d, "blacklisted") }
  end

  test "skips sender domain in URL domain checks" do
    email = create(:email,
      extracted_urls: ["https://example.com/page"],
      sender_domain: "example.com"
    )

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert_equal "completed", layer.status
    domains = get_details(layer, "url_domains") || []
    assert domains.none? { |d| get(d, "domain") == "example.com" }
  end

  test "limits URL domain checks to MAX_DOMAINS_TO_CHECK" do
    urls = (1..8).map { |i| "https://domain#{i}.com/page" }
    email = create(:email, extracted_urls: urls, sender_domain: "example.com")

    urls.each do |url|
      domain = URI.parse(url).host
      stub_whois_api(domain, 1.year.ago.iso8601)
    end

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    domains = get_details(layer, "url_domains") || []
    assert domains.size <= 5
  end

  # --- Attachment scanning ---

  test "scans non-image attachments via VirusTotal file hash" do
    raw = build_email_with_attachment("malware.pdf", "application/pdf", "malicious content here")
    email = create(:email, raw_source: raw, extracted_urls: [])

    sha256 = Digest::SHA256.hexdigest("malicious content here")
    stub_vt_file_hash(sha256, malicious: true, detections: 10)

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert layer.score >= 25, "Malicious attachment should add +25, got #{layer.score}"
    attachments = get_details(layer, "attachments")
    assert attachments.any? { |a| get(a, "filename") == "malware.pdf" && get(a, "malicious") }
  end

  test "skips image attachments" do
    raw = build_email_with_attachment("photo.jpg", "image/jpeg", "fake image data")
    email = create(:email, raw_source: raw, extracted_urls: [])

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert_equal "completed", layer.status
    attachments = get_details(layer, "attachments") || []
    assert_empty attachments
  end

  test "skips image by extension even with generic content type" do
    raw = build_email_with_attachment("logo.png", "application/octet-stream", "png data")
    email = create(:email, raw_source: raw, extracted_urls: [])

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    attachments = get_details(layer, "attachments") || []
    assert_empty attachments
  end

  test "caps malicious attachment score at 50" do
    raw = build_email_with_attachments([
      { filename: "trojan.exe", content_type: "application/octet-stream", body: "evil1" },
      { filename: "backdoor.dll", content_type: "application/octet-stream", body: "evil2" },
      { filename: "virus.scr", content_type: "application/octet-stream", body: "evil3" }
    ])
    email = create(:email, raw_source: raw, extracted_urls: [])

    %w[evil1 evil2 evil3].each do |body|
      sha256 = Digest::SHA256.hexdigest(body)
      stub_vt_file_hash(sha256, malicious: true, detections: 20)
    end

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    # Score from attachments capped at 50 (2 * 25), total capped at 100
    assert layer.score <= 100
    mal_count = get_details(layer, "attachments_malicious_count")
    assert mal_count.present?
    assert mal_count <= 2
  end

  test "handles clean attachments" do
    raw = build_email_with_attachment("report.pdf", "application/pdf", "clean content")
    email = create(:email, raw_source: raw, extracted_urls: [])

    sha256 = Digest::SHA256.hexdigest("clean content")
    stub_vt_file_hash(sha256, malicious: false, detections: 0)

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert_equal 0, layer.score
    attachments = get_details(layer, "attachments")
    assert attachments.any? { |a| get(a, "filename") == "report.pdf" && !get(a, "malicious") }
  end

  # --- Confidence ---

  test "confidence increases with more signals" do
    email = create(:email, extracted_urls: [])
    layer = Analysis::ExternalApiAnalyzer.new(email).analyze
    low_confidence = layer.confidence

    urls = (1..3).map { |i| "https://site#{i}.com/page" }
    email2 = create(:email, extracted_urls: urls, sender_domain: "other.com")
    urls.each do |url|
      domain = URI.parse(url).host
      stub_whois_api(domain, 1.year.ago.iso8601)
    end

    layer2 = Analysis::ExternalApiAnalyzer.new(email2).analyze

    assert layer2.confidence > low_confidence, "More signals should yield higher confidence"
  end

  # --- Explanation ---

  test "explanation includes threat info when threats found" do
    email = create(:email, extracted_urls: ["https://evil.com/phish"], sender_domain: "example.com")

    stub_whois_api("evil.com", 3.days.ago.iso8601)
    set_dns_fake(FakeDnsResolver.new(listed_domains: ["evil.com"]))

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert_includes layer.explanation, "ameaça(s)"
  end

  test "explanation when no threats detected mentions scanned counts" do
    email = create(:email, extracted_urls: ["https://safe.com/page"], sender_domain: "example.com")
    stub_whois_api("safe.com", 1.year.ago.iso8601)

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert_includes layer.explanation, "nenhuma ameaça detectada"
  end

  test "no URLs and no attachments gives clean explanation" do
    email = create(:email, extracted_urls: [], raw_source: "From: a@b.com\nTo: c@d.com\n\nHello")

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert_includes layer.explanation, "Nenhuma URL ou anexo"
  end

  # --- Score cap ---

  test "total score capped at 100" do
    email = create(:email,
      extracted_urls: ["https://evil1.com/a", "https://evil2.com/b", "https://evil3.com/c"],
      sender_domain: "example.com"
    )

    # Make all URLs malicious via URLhaus
    stub_request(:post, "https://urlhaus-api.abuse.ch/v1/url/").to_return(
      status: 200,
      body: { query_status: "listed", threat: "malware_download" }.to_json
    )
    # Make sender domain malicious
    stub_request(:post, "https://urlhaus-api.abuse.ch/v1/host/").to_return(
      status: 200,
      body: { urls_online: 5 }.to_json
    )

    # Flag all domains as young
    %w[evil1.com evil2.com evil3.com].each do |domain|
      stub_whois_api(domain, 2.days.ago.iso8601)
    end

    # Flag all domains as blacklisted
    set_dns_fake(FakeDnsResolver.new(all_listed: true))

    layer = Analysis::ExternalApiAnalyzer.new(email).analyze

    assert_equal 100, layer.score
  end

  private

  def get_details(layer, key)
    layer.details[key.to_s] || layer.details[key.to_sym]
  end

  def get(hash, key)
    hash[key.to_s] || hash[key.to_sym]
  end

  def set_dns_fake(fake)
    Resolv::DNS.instance_variable_set(:@fake_dns_instance, fake)
  end

  def stub_whois_api(domain, created_date)
    stub_request(:get, /whoisxmlapi\.com.*domainName=#{Regexp.escape(domain)}/)
      .to_return(
        status: 200,
        body: {
          WhoisRecord: {
            registryData: { createdDate: created_date },
            registrarName: "Test Registrar"
          }
        }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end

  def stub_vt_file_hash(sha256, malicious:, detections:)
    stub_request(:get, "https://www.virustotal.com/api/v3/files/#{sha256}")
      .to_return(
        status: 200,
        body: {
          data: {
            attributes: {
              last_analysis_stats: {
                "malicious" => malicious ? detections : 0,
                "suspicious" => 0,
                "harmless" => 50,
                "undetected" => 10
              }
            }
          }
        }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end

  def build_email_with_attachment(filename, content_type, body)
    mail = Mail.new do
      from    "sender@example.com"
      to      "recipient@example.com"
      subject "Test with attachment"
      body    "Please see attached"
    end
    mail.attachments[filename] = { mime_type: content_type, content: body }
    mail.to_s
  end

  def build_email_with_attachments(attachments)
    mail = Mail.new do
      from    "sender@example.com"
      to      "recipient@example.com"
      subject "Test with attachments"
      body    "Please see attached files"
    end
    attachments.each do |att|
      mail.attachments[att[:filename]] = { mime_type: att[:content_type], content: att[:body] }
    end
    mail.to_s
  end
end
