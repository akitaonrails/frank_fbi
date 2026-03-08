require "net/http"
require "json"

class WhoisLookupService
  API_BASE = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

  def initialize(domain)
    @domain = domain
  end

  def lookup
    return cached_result if cached_result_fresh?

    response = fetch_whois
    return nil unless response

    parsed = parse_response(response)
    cache_result(parsed)
    parsed
  rescue => e
    Rails.logger.error("WhoisLookupService: Failed for #{@domain}: #{e.message}")
    nil
  end

  private

  def api_key
    ENV.fetch("WHOISXML_API_KEY", "")
  end

  def fetch_whois
    return nil if api_key.blank?

    uri = URI(API_BASE)
    uri.query = URI.encode_www_form(
      apiKey: api_key,
      domainName: @domain,
      outputFormat: "JSON"
    )

    response = Net::HTTP.get_response(uri)
    return nil unless response.is_a?(Net::HTTPSuccess)

    JSON.parse(response.body)
  end

  def parse_response(data)
    record = data.dig("WhoisRecord") || {}
    created = record.dig("registryData", "createdDate") || record.dig("createdDate")
    registrar = record.dig("registrarName")

    domain_age = if created
      ((Time.current - Time.parse(created)) / 1.day).to_i rescue nil
    end

    {
      domain: @domain,
      created_date: created,
      domain_age_days: domain_age,
      registrar: registrar,
      registrant_country: record.dig("registrant", "country"),
      name_servers: record.dig("nameServers", "hostNames"),
      status: record.dig("status")
    }
  end

  def cache_result(parsed)
    known_domain = KnownDomain.find_or_initialize_by(domain: @domain)
    known_domain.update!(
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
