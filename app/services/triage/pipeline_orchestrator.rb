module Triage
  class PipelineOrchestrator
    def self.advance(email)
      new(email).advance
    end

    def initialize(email)
      @email = email
    end

    def advance
      @email.with_lock do
        return if @email.status == "completed" || @email.status == "failed"
        return unless @email.status == "analyzing"

        start_scan_layers
        start_llm_layer
        check_completion
      end
    end

    def start_from_beginning
      @email.update!(status: "analyzing")
      start_scan_layers
    end

    private

    def start_scan_layers
      enqueue_if_ready("triage_url_scan") { TriageUrlScanJob.perform_later(@email.id) }
      enqueue_if_ready("triage_file_scan") { TriageFileScanJob.perform_later(@email.id) }
    end

    def start_llm_layer
      if layer_finished?("triage_url_scan") && layer_finished?("triage_file_scan")
        enqueue_if_ready("triage_llm") { TriageLlmJob.perform_later(@email.id) }
      end
    end

    def check_completion
      return unless all_layers_completed?
      return if @email.final_score.present?

      TriageScoreAggregationJob.perform_later(@email.id)
    end

    def layer_finished?(name)
      @email.analysis_layers.exists?(layer_name: name, status: %w[completed failed])
    end

    def all_layers_completed?
      @email.pipeline_layer_names.all? { |name| layer_finished?(name) }
    end

    def enqueue_if_ready(layer_name)
      existing = @email.analysis_layers.find_by(layer_name: layer_name)
      return if existing && %w[running completed failed].include?(existing.status)

      layer = @email.analysis_layers.find_or_initialize_by(layer_name: layer_name)
      layer.update!(
        weight: AnalysisLayer.default_weight(layer_name),
        status: "running"
      )

      yield
    rescue ActiveRecord::RecordNotUnique
      # Another concurrent advance already created this layer
    end
  end
end
