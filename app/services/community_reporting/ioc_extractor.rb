module CommunityReporting
  class IocExtractor
    # Freemail domains — shared infrastructure, not useful as IOCs
    FREEMAIL_DOMAINS = %w[
      gmail.com yahoo.com hotmail.com outlook.com aol.com icloud.com
      mail.com protonmail.com zoho.com yandex.com live.com msn.com
    ].freeze

    # Well-known cloud provider IP ranges (CIDR prefixes)
    CLOUD_IP_PREFIXES = %w[
      13. 52. 54. 35. 34. 18.
      104.16. 104.17. 104.18. 104.19. 104.20. 104.21. 104.22. 104.23. 104.24.
      172.64. 172.65. 172.66. 172.67.
    ].freeze

    def initialize(email)
      @email = email
      @layers = email.analysis_layers.index_by(&:layer_name)
    end

    def extract
      {
        urls: extract_urls,
        domains: extract_domains,
        ips: extract_ips,
        file_hashes: extract_hashes,
        sender_email: @email.from_address,
        sender_domain: @email.sender_domain
      }
    end

    private

    def extract_urls
      urls = layer_details("content_analysis").fetch("urls", [])
      clean_urls = urls.reject { |url| confirmed_clean?(url) }
      clean_urls.first(20)
    end

    def extract_domains
      domains = layer_details("content_analysis").fetch("url_domains", [])
      domains.reject { |d| FREEMAIL_DOMAINS.include?(d.downcase) }
    end

    def extract_ips
      ip = layer_details("header_auth")["sender_ip"]
      return [] if ip.blank?
      return [] if cloud_ip?(ip)
      [ip]
    end

    def extract_hashes
      attachments = layer_details("external_api").fetch("attachments", [])
      attachments.filter_map { |a| a["sha256"] }.compact
    end

    def layer_details(name)
      @layers[name]&.details || {}
    end

    def confirmed_clean?(url)
      UrlScanResult.where(url: url, malicious: false)
                   .where("detection_count = 0 OR detection_count IS NULL")
                   .exists?
    end

    def cloud_ip?(ip)
      CLOUD_IP_PREFIXES.any? { |prefix| ip.start_with?(prefix) }
    end
  end
end
