class UrlScanResult < ApplicationRecord
  SOURCES = %w[virustotal urlhaus virustotal_file brave_search].freeze

  validates :url, presence: true
  validates :source, presence: true, inclusion: { in: SOURCES },
            uniqueness: { scope: :url }

  scope :fresh, -> { where("expires_at > ?", Time.current) }
  scope :malicious, -> { where(malicious: true) }
  scope :for_url, ->(url) { where(url: url) }

  def expired?
    expires_at.present? && expires_at < Time.current
  end

  def self.cached_result(url, source)
    fresh.find_by(url: url, source: source)
  end
end
