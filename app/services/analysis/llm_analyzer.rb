module Analysis
  class LlmAnalyzer
    LAYER_NAME = "llm_analysis"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]

    MODELS = {
      "anthropic" => "anthropic/claude-sonnet-4-6",
      "openai" => "openai/gpt-4o",
      "xai" => "x-ai/grok-3-mini-beta"
    }.freeze

    def initialize(email)
      @email = email
    end

    def analyze
      # Initialize the layer
      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(weight: WEIGHT, status: "running")

      # Build prompt with all previous layer results
      prior_layers = @email.analysis_layers.where(status: "completed").where.not(layer_name: LAYER_NAME)
      prompt = Prompts::FraudAnalysisPrompt.new(@email, prior_layers).build

      # Enqueue parallel LLM consultations
      MODELS.each do |provider, model_id|
        LlmConsultationJob.perform_later(@email.id, provider, model_id, prompt)
      end
    end

    def self.finalize(email)
      verdicts = email.llm_verdicts.where.not(score: nil)
      return unless verdicts.size >= 2 # Need at least 2 responses

      consensus = LlmConsensusBuilder.new(verdicts).build

      layer = email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(
        score: consensus[:score],
        weight: WEIGHT,
        confidence: consensus[:confidence],
        details: consensus[:details],
        explanation: consensus[:explanation],
        status: "completed"
      )

      PipelineOrchestrator.advance(email)
    end
  end
end
