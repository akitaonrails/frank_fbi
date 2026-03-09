class Email < ApplicationRecord
  encrypts :submitter_email, deterministic: true

  has_many :analysis_layers, dependent: :destroy
  has_many :llm_verdicts, dependent: :destroy
  has_one :analysis_report, dependent: :destroy

  validates :message_id, presence: true, uniqueness: true
  validates :submitter_email, presence: true
  validates :status, presence: true, inclusion: {
    in: %w[pending parsing analyzing completed failed]
  }
  validates :pipeline_type, presence: true, inclusion: {
    in: %w[fraud_analysis messenger_triage]
  }
  validates :verdict, inclusion: {
    in: %w[legitimate suspicious_likely_ok suspicious_likely_fraud fraudulent],
    allow_nil: true
  }
  validates :final_score, numericality: {
    only_integer: true, greater_than_or_equal_to: 0,
    less_than_or_equal_to: 100
  }, allow_nil: true

  scope :pending, -> { where(status: "pending") }
  scope :completed, -> { where(status: "completed") }
  scope :failed, -> { where(status: "failed") }
  scope :fraudulent, -> { where(verdict: "fraudulent") }

  FRAUD_LAYER_NAMES = %w[header_auth sender_reputation content_analysis external_api entity_verification llm_analysis].freeze
  TRIAGE_LAYER_NAMES = %w[triage_url_scan triage_file_scan triage_llm].freeze

  def messenger_triage?
    pipeline_type == "messenger_triage"
  end

  def pipeline_layer_names
    messenger_triage? ? TRIAGE_LAYER_NAMES : FRAUD_LAYER_NAMES
  end

  def fully_analyzed?
    analysis_layers.where(status: "completed").count == pipeline_layer_names.size
  end

  def layer_completed?(layer_name)
    analysis_layers.exists?(layer_name: layer_name, status: "completed")
  end
end
