class KnownDomain < ApplicationRecord
  has_many :known_senders, dependent: :destroy

  validates :domain, presence: true, uniqueness: true
  validates :reputation_score, numericality: {
    only_integer: true, greater_than_or_equal_to: 0,
    less_than_or_equal_to: 100
  }, allow_nil: true

  scope :blacklisted, -> { where("reputation_score < 30") }
  scope :trusted, -> { where("reputation_score > 70") }

  def whois_stale?
    whois_checked_at.nil? || whois_checked_at < 30.days.ago
  end

  def blacklist_stale?
    blacklist_checked_at.nil? || blacklist_checked_at < 7.days.ago
  end

  def fraud_ratio
    return 0.0 if times_seen.zero?
    times_flagged_fraud.to_f / times_seen
  end

  def record_analysis(verdict)
    increment!(:times_seen)
    case verdict
    when "fraudulent", "suspicious_likely_fraud"
      increment!(:times_flagged_fraud)
    when "legitimate", "suspicious_likely_ok"
      increment!(:times_flagged_legit)
    end
  end
end
