require "net/http"
require "json"

module CommunityReporting
  class AbuseipdbClient
    API_BASE = "https://api.abuseipdb.com/api/v2/report"

    # AbuseIPDB category codes
    CATEGORY_EMAIL_SPAM = "11"
    CATEGORY_PHISHING = "9"

    def initialize
      @api_key = ENV.fetch("ABUSEIPDB_API_KEY", "")
    end

    def report_ip(ip, categories: nil, comment: "")
      return nil if @api_key.blank?
      return nil if ip.blank?

      categories ||= "#{CATEGORY_EMAIL_SPAM},#{CATEGORY_PHISHING}"

      uri = URI(API_BASE)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true

      request = Net::HTTP::Post.new(uri)
      request["Key"] = @api_key
      request["Accept"] = "application/json"
      request["Content-Type"] = "application/x-www-form-urlencoded"
      request.body = URI.encode_www_form(
        ip: ip,
        categories: categories,
        comment: comment.truncate(1024)
      )

      response = http.request(request)
      return nil unless response.is_a?(Net::HTTPSuccess)

      data = JSON.parse(response.body)
      { ip: ip, abuse_confidence_score: data.dig("data", "abuseConfidenceScore") }
    rescue => e
      Rails.logger.error("AbuseipdbClient: Failed to report IP #{ip}: #{e.message}")
      nil
    end
  end
end
