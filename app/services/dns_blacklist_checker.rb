require "resolv"

class DnsBlacklistChecker
  BLACKLISTS = {
    "zen.spamhaus.org" => "Spamhaus ZEN",
    "dbl.spamhaus.org" => "Spamhaus DBL",
    "multi.uribl.com" => "URIBL Multi",
    "b.barracudacentral.org" => "Barracuda"
  }.freeze

  IP_BLACKLISTS = %w[zen.spamhaus.org b.barracudacentral.org].freeze
  DOMAIN_BLACKLISTS = %w[dbl.spamhaus.org multi.uribl.com].freeze

  SPAMHAUS_ZEN_CODES = {
    "127.0.0.2" => "sbl",
    "127.0.0.3" => "css",
    "127.0.0.4" => "xbl",
    "127.0.0.9" => "drop",
    "127.0.0.10" => "pbl",
    "127.0.0.11" => "pbl",
    "127.0.0.30" => "bcl"
  }.freeze

  SPAMHAUS_DBL_CODES = {
    "127.0.1.2" => "low_reputation",
    "127.0.1.4" => "phishing",
    "127.0.1.5" => "malware",
    "127.0.1.6" => "botnet_cc",
    "127.0.1.102" => "abused_legit",
    "127.0.1.103" => "abused_redirector",
    "127.0.1.104" => "abused_phishing",
    "127.0.1.105" => "abused_malware",
    "127.0.1.106" => "abused_botnet_cc"
  }.freeze

  # Spamhaus returns these codes when your query is rate-limited or blocked
  SPAMHAUS_ERROR_RANGE_START = "127.255.255.252"
  SPAMHAUS_ERROR_RANGE_END = "127.255.255.255"

  # URIBL valid listing bitmask codes
  URIBL_LISTING_CODES = %w[127.0.0.2 127.0.0.4 127.0.0.8].freeze
  # URIBL returns 127.0.0.1 when query is refused (not paying customer, rate-limited)
  URIBL_REFUSED_CODE = "127.0.0.1"

  # Barracuda valid listing code
  BARRACUDA_LISTING_CODE = "127.0.0.2"

  def initialize(domain, ip: nil)
    @domain = domain
    @ip = ip
  end

  def check
    results = {}

    DOMAIN_BLACKLISTS.each do |bl|
      results[bl] = check_domain_blacklist(@domain, bl)
    end

    if @ip
      IP_BLACKLISTS.each do |bl|
        results[bl] = check_ip_blacklist(@ip, bl)
      end
    end

    cache_results(results)
    results
  rescue => e
    Rails.logger.error("DnsBlacklistChecker: Failed for #{@domain}: #{e.message}")
    {}
  end

  def listed_on_any?
    results = check
    results.values.any? { |r| r[:listed] }
  end

  private

  def check_domain_blacklist(domain, blacklist)
    query = "#{domain}.#{blacklist}"
    lookup(query, blacklist)
  end

  def check_ip_blacklist(ip, blacklist)
    reversed = ip.split(".").reverse.join(".")
    query = "#{reversed}.#{blacklist}"
    lookup(query, blacklist)
  end

  def lookup(query, blacklist)
    resolver = Resolv::DNS.new
    resolver.timeouts = 3
    begin
      addresses = resolver.getaddresses(query)
      response_codes = addresses.map(&:to_s)
      listing = determine_listing(blacklist, response_codes)

      {
        listed: listing[:listed],
        blacklist_name: BLACKLISTS[blacklist],
        response: response_codes,
        categories: spamhaus_categories(blacklist, response_codes),
        authoritative_malicious: listing[:listed] ? authoritative_malicious?(blacklist, response_codes) : false,
        policy_listing: listing[:listed] ? policy_listing?(blacklist, response_codes) : false,
        error: listing[:error]
      }.compact
    rescue Resolv::ResolvError
      { listed: false, blacklist_name: BLACKLISTS[blacklist] }
    ensure
      resolver.close
    end
  end

  def determine_listing(blacklist, response_codes)
    return { listed: false } if response_codes.empty?

    case blacklist
    when "zen.spamhaus.org"
      determine_spamhaus_listing(response_codes, SPAMHAUS_ZEN_CODES)
    when "dbl.spamhaus.org"
      determine_spamhaus_listing(response_codes, SPAMHAUS_DBL_CODES)
    when "multi.uribl.com"
      determine_uribl_listing(response_codes)
    when "b.barracudacentral.org"
      determine_barracuda_listing(response_codes)
    else
      # Unknown blacklist — don't assume listing from unknown codes
      { listed: false, error: "unknown_blacklist" }
    end
  end

  def determine_spamhaus_listing(response_codes, known_codes)
    valid_codes = []
    error_codes = []

    response_codes.each do |code|
      if spamhaus_error_code?(code)
        error_codes << code
      elsif known_codes.key?(code)
        valid_codes << code
      else
        # Unknown code in Spamhaus range — treat as error, not a listing
        error_codes << code
      end
    end

    if valid_codes.any?
      { listed: true }
    elsif error_codes.any?
      { listed: false, error: "rate_limited_or_blocked" }
    else
      { listed: false }
    end
  end

  def determine_uribl_listing(response_codes)
    if response_codes.include?(URIBL_REFUSED_CODE) && (response_codes - [URIBL_REFUSED_CODE]).empty?
      return { listed: false, error: "query_refused" }
    end

    valid_codes = response_codes & URIBL_LISTING_CODES
    if valid_codes.any?
      { listed: true }
    elsif response_codes.any?
      { listed: false, error: "unknown_response_codes" }
    else
      { listed: false }
    end
  end

  def determine_barracuda_listing(response_codes)
    if response_codes.include?(BARRACUDA_LISTING_CODE)
      { listed: true }
    elsif response_codes.any?
      { listed: false, error: "unknown_response_codes" }
    else
      { listed: false }
    end
  end

  def spamhaus_error_code?(code)
    octets = code.split(".").map(&:to_i)
    return false unless octets.size == 4

    # 127.255.255.252 through 127.255.255.255
    octets[0] == 127 && octets[1] == 255 && octets[2] == 255 && octets[3] >= 252
  end

  def spamhaus_categories(blacklist, response_codes)
    case blacklist
    when "zen.spamhaus.org"
      response_codes.filter_map { |code| SPAMHAUS_ZEN_CODES[code] }.uniq
    when "dbl.spamhaus.org"
      response_codes.filter_map { |code| SPAMHAUS_DBL_CODES[code] }.uniq
    else
      []
    end
  end

  def authoritative_malicious?(blacklist, response_codes)
    categories = spamhaus_categories(blacklist, response_codes)

    case blacklist
    when "zen.spamhaus.org"
      (categories & %w[sbl css xbl drop bcl]).any?
    when "dbl.spamhaus.org"
      (categories & %w[phishing malware botnet_cc abused_phishing abused_malware abused_botnet_cc]).any?
    else
      false
    end
  end

  def policy_listing?(blacklist, response_codes)
    blacklist == "zen.spamhaus.org" && spamhaus_categories(blacklist, response_codes).all? { |category| category == "pbl" }
  end

  def cache_results(results)
    known_domain = KnownDomain.find_or_create_by!(domain: @domain) do |d|
      d.times_seen = 0
    end
    known_domain.update!(
      blacklist_results: results,
      blacklist_checked_at: Time.current
    )
  rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
    # Race condition: another job created the record first — retry find
    known_domain = KnownDomain.find_by(domain: @domain)
    known_domain&.update(
      blacklist_results: results,
      blacklist_checked_at: Time.current
    )
  end
end
