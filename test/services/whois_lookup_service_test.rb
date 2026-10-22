require "test_helper"

class WhoisLookupServiceTest < ActiveSupport::TestCase
  setup do
    @original_keys = %w[WHOISXML_API_KEY OTILABS_API_KEY WHOISFREAKS_API_KEY].to_h { |k| [k, ENV[k]] }
    %w[WHOISXML_API_KEY OTILABS_API_KEY WHOISFREAKS_API_KEY].each { |k| ENV[k] = "" }
    KnownDomain.delete_all
  end

  teardown do
    @original_keys.each { |key, value| ENV[key] = value }
  end

  test "returns nil without any provider key and makes no request" do
    assert_nil WhoisLookupService.new("example.com").lookup
    assert_not_requested :get, /whoisxmlapi\.com|rapidapi\.com|whoisfreaks\.com/
  end

  test "any_provider_configured? reflects each key" do
    refute WhoisLookupService.any_provider_configured?

    ENV["OTILABS_API_KEY"] = "k"
    assert WhoisLookupService.any_provider_configured?

    ENV["OTILABS_API_KEY"] = ""
    ENV["WHOISFREAKS_API_KEY"] = "k"
    assert WhoisLookupService.any_provider_configured?
  end

  test "uses WhoisXML when its key is set, even if fallback keys are also set" do
    ENV["WHOISXML_API_KEY"] = "xml-key"
    ENV["OTILABS_API_KEY"] = "oti-key"
    ENV["WHOISFREAKS_API_KEY"] = "freaks-key"

    stub_request(:get, "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=xml-key&domainName=example.com&outputFormat=JSON")
      .to_return(body: { WhoisRecord: {
        registryData: { createdDate: 10.days.ago.utc.iso8601 },
        registrarName: "Example Registrar, LLC",
        registrant: { country: "US" },
        nameServers: { hostNames: ["ns1.example.com"] },
        status: "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"
      } }.to_json)

    result = WhoisLookupService.new("example.com").lookup

    assert_equal 10, result[:domain_age_days]
    assert_equal "Example Registrar, LLC", result[:registrar]
    assert_equal "US", result[:registrant_country]
    assert_not_requested :get, /rapidapi\.com/
    assert_not_requested :get, /whoisfreaks\.com/
  end

  test "falls back to OTILabs when only OTILABS_API_KEY is set" do
    ENV["OTILABS_API_KEY"] = "oti-key"

    stub_request(:get, "https://domain-intelligence-api.p.rapidapi.com/domain/example.com/whois")
      .with(headers: { "X-RapidAPI-Key" => "oti-key" })
      .to_return(body: {
        registrar: "RESERVED-Internet Assigned Numbers Authority",
        created: 45.days.ago.utc.iso8601,
        nameservers: ["ELLIOTT.NS.CLOUDFLARE.COM"],
        status: ["client transfer prohibited"]
      }.to_json)

    result = WhoisLookupService.new("example.com").lookup

    assert_equal 45, result[:domain_age_days]
    assert_equal "RESERVED-Internet Assigned Numbers Authority", result[:registrar]
    assert_nil result[:registrant_country]
    assert_equal ["ELLIOTT.NS.CLOUDFLARE.COM"], result[:name_servers]
    assert_not_requested :get, /whoisxmlapi\.com/
  end

  test "falls back to WhoisFreaks when only WHOISFREAKS_API_KEY is set" do
    ENV["WHOISFREAKS_API_KEY"] = "freaks-key"

    stub_request(:get, "https://api.whoisfreaks.com/v2.0/whois/live?apiKey=freaks-key&whois=live&domainName=example.com&format=json")
      .to_return(body: {
        create_date: 5.days.ago.to_date.to_s,
        domain_registrar: { registrar_name: "Example Registrar, LLC" },
        registrant_contact: { country_code: "BR" },
        name_servers: ["ns1.example.com"],
        domain_status: ["active"]
      }.to_json)

    result = WhoisLookupService.new("example.com").lookup

    assert_equal 5, result[:domain_age_days]
    assert_equal "Example Registrar, LLC", result[:registrar]
    assert_equal "BR", result[:registrant_country]
    assert_not_requested :get, /whoisxmlapi\.com/
  end

  test "tries the next configured provider when the primary request fails" do
    ENV["WHOISXML_API_KEY"] = "xml-key"
    ENV["OTILABS_API_KEY"] = "oti-key"

    stub_request(:get, /whoisxmlapi\.com/).to_return(status: 500)
    stub_request(:get, "https://domain-intelligence-api.p.rapidapi.com/domain/example.com/whois")
      .to_return(body: { registrar: "Backup Registrar", created: 2.days.ago.utc.iso8601 }.to_json)

    result = WhoisLookupService.new("example.com").lookup

    assert_equal 2, result[:domain_age_days]
    assert_equal "Backup Registrar", result[:registrar]
    assert_requested :get, /whoisxmlapi\.com/
  end

  test "caches a successful lookup for 30 days and skips the provider" do
    ENV["WHOISXML_API_KEY"] = "xml-key"

    KnownDomain.create!(
      domain: "example.com",
      times_seen: 1,
      whois_data: { "domain" => "example.com", "domain_age_days" => 300 },
      domain_age_days: 300,
      whois_checked_at: 2.days.ago
    )

    result = WhoisLookupService.new("example.com").lookup

    assert_equal 300, result["domain_age_days"]
    assert_not_requested :get, /whoisxmlapi\.com/
  end
end
