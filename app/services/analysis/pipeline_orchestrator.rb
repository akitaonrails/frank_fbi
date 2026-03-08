module Analysis
  class PipelineOrchestrator
    # Pipeline stages and their dependencies:
    # 1. header_auth: no dependencies (can start immediately)
    # 2. sender_reputation: depends on header_auth (for sender IP)
    # 3. content_analysis: no dependencies (can start with header_auth)
    # 4. external_api: depends on content_analysis (for extracted URLs)
    # 5. llm_analysis: depends on all of 1-4

    def self.advance(email)
      new(email).advance
    end

    def initialize(email)
      @email = email
    end

    def advance
      return if @email.status == "completed" || @email.status == "failed"
      return unless @email.status == "analyzing"

      start_initial_layers
      start_dependent_layers
      check_completion
    end

    def start_from_beginning
      @email.update!(status: "analyzing")
      start_initial_layers
    end

    private

    def start_initial_layers
      # Layer 1 (header_auth) and Layer 3 (content_analysis) can start immediately
      enqueue_if_ready("header_auth") { HeaderAuthAnalysisJob.perform_later(@email.id) }
      enqueue_if_ready("content_analysis") { ContentAnalysisJob.perform_later(@email.id) }
    end

    def start_dependent_layers
      # Layer 2 (sender_reputation) can start after Layer 1
      if layer_completed?("header_auth")
        enqueue_if_ready("sender_reputation") { SenderReputationAnalysisJob.perform_later(@email.id) }
      end

      # Layer 4 (external_api) needs Layer 3 for URLs
      if layer_completed?("content_analysis")
        enqueue_if_ready("external_api") { ExternalApiAnalysisJob.perform_later(@email.id) }
      end

      # Layer 5 (llm_analysis) needs all of 1-4
      if layers_1_to_4_completed?
        enqueue_if_ready("llm_analysis") { LlmAnalysisJob.perform_later(@email.id) }
      end
    end

    def check_completion
      return unless all_layers_completed?

      # All layers done — aggregate score and generate report
      ScoreAggregationJob.perform_later(@email.id)
    end

    def layer_completed?(name)
      @email.analysis_layers.exists?(layer_name: name, status: "completed")
    end

    def layers_1_to_4_completed?
      %w[header_auth sender_reputation content_analysis external_api].all? do |name|
        layer_completed?(name)
      end
    end

    def all_layers_completed?
      AnalysisLayer::LAYER_NAMES.all? { |name| layer_completed?(name) }
    end

    def enqueue_if_ready(layer_name)
      # Don't re-enqueue if already running or completed
      existing = @email.analysis_layers.find_by(layer_name: layer_name)
      return if existing && %w[running completed].include?(existing.status)

      # Create or update the layer record
      layer = @email.analysis_layers.find_or_initialize_by(layer_name: layer_name)
      layer.update!(
        weight: AnalysisLayer.default_weight(layer_name),
        status: "running"
      )

      yield
    end
  end
end
