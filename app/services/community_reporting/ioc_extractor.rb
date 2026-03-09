module CommunityReporting
  class IocExtractor
    # Freemail domains — shared infrastructure, not useful as IOCs
    FREEMAIL_DOMAINS = %w[
      gmail.com yahoo.com hotmail.com outlook.com aol.com icloud.com
      mail.com protonmail.com zoho.com yandex.com live.com msn.com
    ].freeze

    # Well-known legitimate domains — too high-profile to report as IOCs.
    # Attackers embed these in spam to poison threat intel databases.
    WELL_KNOWN_DOMAINS = %w[
      microsoft.com apple.com google.com amazon.com facebook.com
      twitter.com x.com linkedin.com instagram.com youtube.com
      netflix.com spotify.com dropbox.com github.com slack.com
      zoom.us salesforce.com adobe.com oracle.com ibm.com
      paypal.com stripe.com square.com shopify.com ebay.com
      walmart.com target.com bestbuy.com
      chase.com bankofamerica.com wellsfargo.com citibank.com
      gov.br gov.uk gov.us irs.gov usa.gov whitehouse.gov
      who.int un.org europa.eu
      wikipedia.org archive.org
      cloudflare.com akamai.com fastly.com
    ].freeze

    # Infrastructure IP prefixes — email MTAs and cloud providers.
    # Reporting these as malicious creates false positives in AbuseIPDB.
    INFRASTRUCTURE_IP_PREFIXES = %w[
      13. 52. 54. 35. 34. 18.
      104.16. 104.17. 104.18. 104.19. 104.20. 104.21. 104.22. 104.23. 104.24.
      172.64. 172.65. 172.66. 172.67.
      64.233. 74.125. 209.85. 142.250. 172.217. 216.58. 216.239.
      40.92. 40.107. 104.47.
      167.89.
      199.255.
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
      domains.reject { |d| excluded_domain?(d.downcase) }
    end

    def extract_ips
      ip = layer_details("header_auth")["sender_ip"]
      return [] if ip.blank?
      return [] if infrastructure_ip?(ip)
      [ip]
    end

    def extract_hashes
      attachments = layer_details("external_api").fetch("attachments", [])
      attachments.filter_map { |a| a["sha256"] }.compact
    end

    def layer_details(name)
      @layers[name]&.details || {}
    end

    def excluded_domain?(domain)
      FREEMAIL_DOMAINS.include?(domain) ||
        WELL_KNOWN_DOMAINS.include?(domain) ||
        domain_confirmed_all_clean?(domain)
    end

    def confirmed_clean?(url)
      UrlScanResult.where(url: url, malicious: false)
                   .where("detection_count = 0 OR detection_count IS NULL")
                   .exists?
    end

    # A domain is considered clean if ALL its scanned URLs came back clean
    def domain_confirmed_all_clean?(domain)
      scans = UrlScanResult.where("url LIKE ?", "%://#{domain}%")
      return false if scans.empty?

      scans.where(malicious: true).or(scans.where("detection_count > 0")).empty?
    end

    def infrastructure_ip?(ip)
      INFRASTRUCTURE_IP_PREFIXES.any? { |prefix| ip.start_with?(prefix) }
    end
  end
end
