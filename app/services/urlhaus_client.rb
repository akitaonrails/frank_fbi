require "net/http"
require "json"

class UrlhausClient
  API_BASE = "https://urlhaus-api.abuse.ch/v1"
  CACHE_TTL = 12.hours

  def scan_url(url)
    cached = UrlScanResult.cached_result(url, "urlhaus")
    return cached_to_result(cached) if cached

    response = query_url(url)
    return nil unless response

    result = parse_response(response, url)
    cache_result(url, result)
    result
  rescue => e
    Rails.logger.error("UrlhausClient: Failed for #{url}: #{e.message}")
    nil
  end

  def scan_domain(domain)
    response = query_host(domain)
    return nil unless response
    parse_host_response(response, domain)
  rescue => e
    Rails.logger.error("UrlhausClient: Failed for domain #{domain}: #{e.message}")
    nil
  end

  private

  def query_url(url)
    uri = URI("#{API_BASE}/url/")
    response = Net::HTTP.post_form(uri, { url: url })
    return nil unless response.is_a?(Net::HTTPSuccess)
    JSON.parse(response.body)
  end

  def query_host(host)
    uri = URI("#{API_BASE}/host/")
    response = Net::HTTP.post_form(uri, { host: host })
    return nil unless response.is_a?(Net::HTTPSuccess)
    JSON.parse(response.body)
  end

  def parse_response(data, url)
    status = data["query_status"]
    threat = data["threat"]

    {
      url: url,
      malicious: status == "listed",
      threat_type: threat,
      tags: data["tags"],
      date_added: data["date_added"],
      source: "urlhaus"
    }
  end

  def parse_host_response(data, domain)
    url_count = data["urls_online"]&.to_i || 0
    {
      domain: domain,
      malicious: url_count > 0,
      urls_online: url_count,
      blacklists: data["blacklists"],
      source: "urlhaus"
    }
  end

  def cache_result(url, result)
    domain = URI.parse(url).host rescue nil

    UrlScanResult.find_or_initialize_by(url: url, source: "urlhaus").update!(
      domain: domain,
      malicious: result[:malicious],
      detection_count: result[:malicious] ? 1 : 0,
      scan_details: result,
      expires_at: CACHE_TTL.from_now
    )
  rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
    UrlScanResult.find_by(url: url, source: "urlhaus")&.update(
      domain: domain,
      malicious: result[:malicious],
      detection_count: result[:malicious] ? 1 : 0,
      scan_details: result,
      expires_at: CACHE_TTL.from_now
    )
  end

  def cached_to_result(cached)
    {
      url: cached.url,
      malicious: cached.malicious,
      source: "urlhaus",
      cached: true
    }
  end
end
