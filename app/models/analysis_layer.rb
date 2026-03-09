class AnalysisLayer < ApplicationRecord
  LAYER_NAMES = %w[
    header_auth
    sender_reputation
    content_analysis
    external_api
    entity_verification
    llm_analysis
  ].freeze

  WEIGHTS = {
    "header_auth" => 0.15,
    "sender_reputation" => 0.15,
    "content_analysis" => 0.15,
    "external_api" => 0.15,
    "entity_verification" => 0.10,
    "llm_analysis" => 0.30
  }.freeze

  belongs_to :email

  validates :layer_name, presence: true, inclusion: { in: LAYER_NAMES },
            uniqueness: { scope: :email_id }
  validates :weight, presence: true, numericality: { greater_than: 0, less_than_or_equal_to: 1 }
  validates :score, numericality: {
    only_integer: true, greater_than_or_equal_to: 0,
    less_than_or_equal_to: 100
  }, allow_nil: true
  validates :confidence, numericality: {
    greater_than_or_equal_to: 0, less_than_or_equal_to: 1
  }
  validates :status, presence: true, inclusion: {
    in: %w[pending running completed failed]
  }

  scope :completed, -> { where(status: "completed") }
  scope :for_layer, ->(name) { find_by(layer_name: name) }

  def self.default_weight(layer_name)
    WEIGHTS.fetch(layer_name)
  end
end
