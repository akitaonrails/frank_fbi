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
      listed = addresses.any?
      response_codes = addresses.map(&:to_s)
      {
        listed: listed,
        blacklist_name: BLACKLISTS[blacklist],
        response: response_codes,
        categories: spamhaus_categories(blacklist, response_codes),
        authoritative_malicious: authoritative_malicious?(blacklist, response_codes),
        policy_listing: policy_listing?(blacklist, response_codes)
      }
    rescue Resolv::ResolvError
      { listed: false, blacklist_name: BLACKLISTS[blacklist] }
    ensure
      resolver.close
    end
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
