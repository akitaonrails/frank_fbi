class AddContentPatternsToLlmVerdicts < ActiveRecord::Migration[8.1]
  def change
    add_column :llm_verdicts, :content_patterns, :json, default: {}
  end
end
