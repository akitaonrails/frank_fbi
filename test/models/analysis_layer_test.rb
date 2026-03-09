require "test_helper"

class AnalysisLayerTest < ActiveSupport::TestCase
  test "validates layer_name inclusion" do
    layer = build(:analysis_layer, layer_name: "invalid")
    assert_not layer.valid?
  end

  test "validates uniqueness of layer_name per email" do
    email = create(:email)
    create(:analysis_layer, email: email, layer_name: "header_auth")
    duplicate = build(:analysis_layer, email: email, layer_name: "header_auth")
    assert_not duplicate.valid?
  end

  test "validates score range" do
    assert build(:analysis_layer, score: 0).valid?
    assert build(:analysis_layer, score: 100).valid?
    assert_not build(:analysis_layer, score: -1).valid?
    assert_not build(:analysis_layer, score: 101).valid?
  end

  test "validates confidence range" do
    assert build(:analysis_layer, confidence: 0.0).valid?
    assert build(:analysis_layer, confidence: 1.0).valid?
    assert_not build(:analysis_layer, confidence: -0.1).valid?
    assert_not build(:analysis_layer, confidence: 1.1).valid?
  end

  test "default_weight returns correct weights" do
    assert_equal 0.15, AnalysisLayer.default_weight("header_auth")
    assert_equal 0.15, AnalysisLayer.default_weight("content_analysis")
    assert_equal 0.15, AnalysisLayer.default_weight("external_api")
    assert_equal 0.30, AnalysisLayer.default_weight("llm_analysis")
    assert_equal 0.10, AnalysisLayer.default_weight("entity_verification")
  end

  test "LAYER_NAMES contains all 6 layers" do
    assert_equal 6, AnalysisLayer::LAYER_NAMES.size
    assert_includes AnalysisLayer::LAYER_NAMES, "header_auth"
    assert_includes AnalysisLayer::LAYER_NAMES, "content_analysis"
    assert_includes AnalysisLayer::LAYER_NAMES, "entity_verification"
    assert_includes AnalysisLayer::LAYER_NAMES, "llm_analysis"
  end
end
