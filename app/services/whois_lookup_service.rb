require "net/http"
require "json"

class WhoisLookupService
  API_BASE = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
  OTILABS_API_BASE = "https://domain-intelligence-api.p.rapidapi.com/domain"
  OTILABS_API_HOST = "domain-intelligence-api.p.rapidapi.com"
  WHOISFREAKS_API_BASE = "https://api.whoisfreaks.com/v2.0/whois/live"

  # Ordered fallback chain: the first provider with a configured API key is
  # used; if its request fails, the next configured provider is tried.
  PROVIDER_KEYS = {
    whoisxml: "WHOISXML_API_KEY",
    otilabs: "OTILABS_API_KEY",
    whoisfreaks: "WHOISFREAKS_API_KEY"
  }.freeze

  def initialize(domain)
    @domain = domain
  end

  def self.any_provider_configured?
    PROVIDER_KEYS.values.any? { |key| ENV.fetch(key, "").present? }
  end

  def lookup
    return cached_result if cached_result_fresh?

    configured_providers.each do |provider|
      data = fetch_from(provider)
      next unless data

      parsed = parse_response(data, provider)
      cache_result(parsed)
      return parsed
    end

    nil
  rescue => e
    Rails.logger.error("WhoisLookupService: Failed for #{@domain}: #{e.message}")
    nil
  end

  private

  def configured_providers
    PROVIDER_KEYS.filter_map { |provider, env_key| provider if ENV.fetch(env_key, "").present? }
  end

  def fetch_from(provider)
    case provider
    when :whoisxml then fetch_json(build_uri(API_BASE,
        apiKey: ENV.fetch("WHOISXML_API_KEY", ""),
        domainName: @domain,
        outputFormat: "JSON"))
    when :otilabs
      uri = URI("#{OTILABS_API_BASE}/#{@domain}/whois")
      request = Net::HTTP::Get.new(uri)
      request["X-RapidAPI-Host"] = OTILABS_API_HOST
      request["X-RapidAPI-Key"] = ENV.fetch("OTILABS_API_KEY", "")
      perform_request(uri, request)
    when :whoisfreaks then fetch_json(build_uri(WHOISFREAKS_API_BASE,
        apiKey: ENV.fetch("WHOISFREAKS_API_KEY", ""),
        whois: "live",
        domainName: @domain,
        format: "json"))
    end
  end

  def build_uri(base, params)
    uri = URI(base)
    uri.query = URI.encode_www_form(params)
    uri
  end

  def fetch_json(uri)
    perform_request(uri, Net::HTTP::Get.new(uri))
  end

  def perform_request(uri, request)
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 5, read_timeout: 10) do |http|
      http.request(request)
    end
    return nil unless response.is_a?(Net::HTTPSuccess)

    JSON.parse(response.body)
  end

  def parse_response(data, provider)
    case provider
    when :whoisxml then parse_whoisxml(data)
    when :otilabs then parse_otilabs(data)
    when :whoisfreaks then parse_whoisfreaks(data)
    end
  end

  def parse_whoisxml(data)
    record = data.dig("WhoisRecord") || {}
    created = record.dig("registryData", "createdDate") || record.dig("createdDate")

    {
      domain: @domain,
      created_date: created,
      domain_age_days: domain_age_days(created),
      registrar: record.dig("registrarName"),
      registrant_country: record.dig("registrant", "country"),
      name_servers: record.dig("nameServers", "hostNames"),
      status: record.dig("status")
    }
  end

  def parse_otilabs(data)
    created = data["created"]

    {
      domain: @domain,
      created_date: created,
      domain_age_days: domain_age_days(created),
      registrar: data["registrar"],
      registrant_country: nil, # OTILabs does not return registrant contact details
      name_servers: data["nameservers"],
      status: data["status"]
    }
  end

  def parse_whoisfreaks(data)
    created = data["create_date"]

    {
      domain: @domain,
      created_date: created,
      domain_age_days: domain_age_days(created),
      registrar: data.dig("domain_registrar", "registrar_name"),
      registrant_country: data.dig("registrant_contact", "country_code"),
      name_servers: data["name_servers"],
      status: data["domain_status"]
    }
  end

  def domain_age_days(created)
    return nil unless created

    ((Time.current - Time.parse(created)) / 1.day).to_i
  rescue ArgumentError
    nil
  end

  def cache_result(parsed)
    known_domain = KnownDomain.find_or_create_by!(domain: @domain) do |d|
      d.times_seen = 0
    end
    known_domain.update!(
      whois_data: parsed,
      domain_age_days: parsed[:domain_age_days],
      whois_checked_at: Time.current
    )
  rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
    # Race condition: another job created the record first — retry find
    known_domain = KnownDomain.find_by(domain: @domain)
    known_domain&.update(
      whois_data: parsed,
      domain_age_days: parsed[:domain_age_days],
      whois_checked_at: Time.current
    )
  end

  def cached_result_fresh?
    known_domain = KnownDomain.find_by(domain: @domain)
    known_domain&.whois_checked_at&.> 30.days.ago
  end

  def cached_result
    known_domain = KnownDomain.find_by(domain: @domain)
    known_domain&.whois_data if cached_result_fresh?
  end
end
