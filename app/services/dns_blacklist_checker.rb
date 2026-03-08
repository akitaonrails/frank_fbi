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
      {
        listed: listed,
        blacklist_name: BLACKLISTS[blacklist],
        response: addresses.map(&:to_s)
      }
    rescue Resolv::ResolvError
      { listed: false, blacklist_name: BLACKLISTS[blacklist] }
    ensure
      resolver.close
    end
  end

  def cache_results(results)
    known_domain = KnownDomain.find_or_initialize_by(domain: @domain)
    known_domain.update!(
      blacklist_results: results,
      blacklist_checked_at: Time.current
    )
  end
end
