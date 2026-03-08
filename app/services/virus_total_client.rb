require "net/http"
require "json"

class VirusTotalClient
  API_BASE = "https://www.virustotal.com/api/v3"
  CACHE_TTL = 24.hours

  def initialize
    @api_key = ENV.fetch("VIRUSTOTAL_API_KEY", "")
  end

  def scan_url(url)
    cached = UrlScanResult.cached_result(url, "virustotal")
    return cached_to_result(cached) if cached

    return nil if @api_key.blank?

    response = submit_url(url)
    return nil unless response

    result = parse_response(response, url)
    cache_result(url, result)
    result
  rescue => e
    Rails.logger.error("VirusTotalClient: Failed for #{url}: #{e.message}")
    nil
  end

  private

  def submit_url(url)
    uri = URI("#{API_BASE}/urls")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    request = Net::HTTP::Post.new(uri)
    request["x-apikey"] = @api_key
    request["Content-Type"] = "application/x-www-form-urlencoded"
    request.body = "url=#{URI.encode_www_form_component(url)}"

    response = http.request(request)
    return nil unless response.is_a?(Net::HTTPSuccess)

    data = JSON.parse(response.body)
    analysis_id = data.dig("data", "id")
    return nil unless analysis_id

    # Wait briefly then fetch results
    sleep(2)
    fetch_analysis(analysis_id)
  end

  def fetch_analysis(analysis_id)
    uri = URI("#{API_BASE}/analyses/#{analysis_id}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    request = Net::HTTP::Get.new(uri)
    request["x-apikey"] = @api_key

    response = http.request(request)
    return nil unless response.is_a?(Net::HTTPSuccess)

    JSON.parse(response.body)
  end

  def parse_response(data, url)
    stats = data.dig("data", "attributes", "stats") || {}
    malicious = (stats["malicious"] || 0) + (stats["suspicious"] || 0)
    total = stats.values.sum

    {
      url: url,
      malicious: malicious > 0,
      detection_count: malicious,
      total_scanners: total,
      stats: stats,
      source: "virustotal"
    }
  end

  def cache_result(url, result)
    domain = URI.parse(url).host rescue nil

    UrlScanResult.find_or_initialize_by(url: url, source: "virustotal").update!(
      domain: domain,
      malicious: result[:malicious],
      detection_count: result[:detection_count],
      scan_details: result,
      expires_at: CACHE_TTL.from_now
    )
  end

  def cached_to_result(cached)
    {
      url: cached.url,
      malicious: cached.malicious,
      detection_count: cached.detection_count,
      source: "virustotal",
      cached: true
    }
  end
end
