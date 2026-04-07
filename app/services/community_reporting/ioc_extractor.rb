require "ipaddr"

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

    # Infrastructure IP CIDR ranges — email MTAs and cloud providers.
    # Reporting these as malicious creates false positives in AbuseIPDB.
    # Uses precise CIDR notation instead of string prefixes to avoid
    # overly broad matching (e.g. "13." matched 16.7M IPs).
    INFRASTRUCTURE_IP_CIDRS = [
      # AWS — major service ranges (CloudFront, EC2, ELB, SES)
      "13.32.0.0/14",    # CloudFront
      "13.224.0.0/14",   # CloudFront
      "13.248.0.0/16",   # Global Accelerator
      "52.0.0.0/11",     # EC2 us-east
      "52.44.0.0/15",    # EC2
      "52.92.0.0/14",    # S3
      "54.64.0.0/11",    # EC2
      "54.160.0.0/11",   # EC2
      "54.192.0.0/12",   # CloudFront
      "54.230.0.0/15",   # CloudFront
      "35.72.0.0/13",    # EC2 ap-northeast
      "35.152.0.0/14",   # EC2
      "34.192.0.0/10",   # EC2 us-east
      "18.64.0.0/14",    # CloudFront
      "18.204.0.0/14",   # EC2
      # Cloudflare
      "104.16.0.0/13",   # 104.16-104.23
      "104.24.0.0/14",   # 104.24-104.27
      "172.64.0.0/13",   # 172.64-172.71
      # Google MTA / Workspace
      "64.233.160.0/19",
      "74.125.0.0/16",
      "209.85.128.0/17",
      "142.250.0.0/15",
      "172.217.0.0/16",
      "216.58.192.0/19",
      "216.239.32.0/19",
      # Microsoft Exchange Online
      "40.92.0.0/15",
      "40.107.0.0/16",
      "104.47.0.0/17",
      # SendGrid
      "167.89.0.0/17",
      # SparkPost
      "199.255.192.0/22",
    ].map { |cidr| IPAddr.new(cidr) }.freeze

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
      escaped = ActiveRecord::Base.sanitize_sql_like(domain)
      scans = UrlScanResult.where("url LIKE ?", "%://#{escaped}%")
      return false if scans.empty?

      scans.where(malicious: true).or(scans.where("detection_count > 0")).empty?
    end

    def infrastructure_ip?(ip)
      parsed = IPAddr.new(ip)
      INFRASTRUCTURE_IP_CIDRS.any? { |cidr| cidr.include?(parsed) }
    rescue IPAddr::InvalidAddressError
      false
    end
  end
end
